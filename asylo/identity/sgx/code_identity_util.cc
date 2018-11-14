/*
 *
 * Copyright 2017 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "asylo/identity/sgx/code_identity_util.h"

#include <openssl/cmac.h>
#include <limits>
#include <string>

#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sgx/attributes.pb.h"
#include "asylo/identity/sgx/attributes_util.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/hardware_interface.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/self_identity.h"
#include "asylo/identity/util/sha256_hash.pb.h"
#include "asylo/identity/util/sha256_hash_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

// Retrieves the report key associated with |keyid| for the current enclave and
// writes it to |key|.
Status GetReportKey(const UnsafeBytes<kKeyrequestKeyidSize> &keyid,
                    HardwareKey *key) {
  if (!AlignedHardwareKeyPtr::IsAligned(key)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Output parameter |key| is not properly aligned");
  }

  // Set KEYREQUEST to request the REPORT_KEY with the KEYID value specified in
  // the report to be verified.
  AlignedKeyrequestPtr request;

  request->keyname = KeyrequestKeyname::REPORT_KEY;
  request->keyid = keyid;

  // SGX hardware requires that the reserved fields of KEYREQUEST be set to
  // zero.
  request->reserved1.fill(0);
  request->reserved2.fill(0);

  // The following fields of KEYREQUEST are ignored by the SGX hardware. These
  // are just initialized to some sane values.
  request->keypolicy = kKeypolicyMrenclaveBitMask;
  request->isvsvn = 0;
  request->cpusvn.fill(0);
  ClearSecsAttributeSet(&request->attributemask);
  request->miscmask = 0;

  if (!GetHardwareKey(*request, key)) {
    return Status(::asylo::error::GoogleError::INTERNAL,
                  "Could not get required hardware key");
  }

  return Status::OkStatus();
}

}  // namespace

namespace internal {

bool IsIdentityCompatibleWithMatchSpec(const CodeIdentity &identity,
                                       const CodeIdentityMatchSpec &spec) {
  if (spec.is_mrenclave_match_required() && !identity.has_mrenclave()) {
    return false;
  }
  if (spec.is_mrsigner_match_required() &&
      !identity.signer_assigned_identity().has_mrsigner()) {
    return false;
  }
  return true;
}

}  // namespace internal

StatusOr<bool> MatchIdentityToExpectation(
    const CodeIdentity &identity, const CodeIdentityExpectation &expectation) {
  const CodeIdentity &expected = expectation.reference_identity();
  const CodeIdentityMatchSpec &spec = expectation.match_spec();

  if (!IsValidExpectation(expectation)) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Expectation parameter is invalid");
  }
  if (!IsValidCodeIdentity(identity)) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Identity parameter is invalid");
  }
  if (!internal::IsIdentityCompatibleWithMatchSpec(identity, spec)) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Identity is not compatible with specified match spec");
  }

  if (spec.is_mrenclave_match_required() &&
      identity.mrenclave() != expected.mrenclave()) {
    return false;
  }

  const SignerAssignedIdentity &given_id = identity.signer_assigned_identity();
  const SignerAssignedIdentity &expected_id =
      expected.signer_assigned_identity();

  if (spec.is_mrsigner_match_required() &&
      given_id.mrsigner() != expected_id.mrsigner()) {
    return false;
  }

  if (given_id.isvprodid() != expected_id.isvprodid()) {
    return false;
  }
  if (given_id.isvsvn() < expected_id.isvsvn()) {
    return false;
  }

  if ((spec.miscselect_match_mask() & identity.miscselect()) !=
      (spec.miscselect_match_mask() & expected.miscselect())) {
    return false;
  }

  if ((spec.attributes_match_mask() & identity.attributes()) !=
      (spec.attributes_match_mask() & expected.attributes())) {
    return false;
  }

  return true;
}

Status SetExpectation(const CodeIdentityMatchSpec &match_spec,
                      const CodeIdentity &identity,
                      CodeIdentityExpectation *expectation) {
  if (!IsValidMatchSpec(match_spec)) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Match spec is invalid");
  }
  if (!IsValidCodeIdentity(identity)) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Identity is invalid");
  }

  *expectation->mutable_match_spec() = match_spec;
  *expectation->mutable_reference_identity() = identity;
  return Status::OkStatus();
}

bool IsValidSignerAssignedIdentity(const SignerAssignedIdentity &identity) {
  return (identity.has_isvprodid() && identity.has_isvsvn());
}

bool IsValidCodeIdentity(const CodeIdentity &identity) {
  // mrenclave is optional. Only the mrsigner part of the signer-assigned
  // identity is optional. miscselect and attributes are required fields.
  if (!identity.has_signer_assigned_identity() ||
      !IsValidSignerAssignedIdentity(identity.signer_assigned_identity())) {
    return false;
  }

  return identity.has_miscselect() && identity.has_attributes();
}

bool IsValidMatchSpec(const CodeIdentityMatchSpec &match_spec) {
  return match_spec.has_is_mrenclave_match_required() &&
         match_spec.has_is_mrsigner_match_required() &&
         match_spec.has_miscselect_match_mask() &&
         match_spec.has_attributes_match_mask();
}

bool IsValidExpectation(const CodeIdentityExpectation &expectation) {
  const CodeIdentityMatchSpec &spec = expectation.match_spec();
  if (!IsValidMatchSpec(spec)) {
    return false;
  }
  const CodeIdentity &identity = expectation.reference_identity();
  if (!IsValidCodeIdentity(identity)) {
    return false;
  }
  return internal::IsIdentityCompatibleWithMatchSpec(identity, spec);
}

Status ParseIdentityFromHardwareReport(const Report &report,
                                       CodeIdentity *identity) {
  identity->mutable_mrenclave()->set_hash(report.mrenclave.data(),
                                          report.mrenclave.size());
  identity->mutable_signer_assigned_identity()->mutable_mrsigner()->set_hash(
      report.mrsigner.data(), report.mrsigner.size());
  identity->mutable_signer_assigned_identity()->set_isvprodid(report.isvprodid);
  identity->mutable_signer_assigned_identity()->set_isvsvn(report.isvsvn);
  if (!ConvertSecsAttributeRepresentation(report.attributes,
                                          identity->mutable_attributes())) {
    return Status(::asylo::error::GoogleError::INTERNAL,
                  "Cound not convert hardware attributes to Attributes proto");
  }
  identity->set_miscselect(report.miscselect);
  return Status::OkStatus();
}

Status SetDefaultMatchSpec(CodeIdentityMatchSpec *spec) {
  // Do not require MRENCLAVE match, as the value of MRENCLAVE changes from one
  // version of the enclave to another.
  spec->set_is_mrenclave_match_required(false);

  // Require MRSIGNER match.
  spec->set_is_mrsigner_match_required(true);

  // All MISCSELECT bits are considered security critical. This is because,
  // currently only one MISCSELECT bit is defined, which is security critical,
  // and all undefined bits are, by default, considered security-critical, as
  // they could be defined to affect security in the future.
  spec->set_miscselect_match_mask(std::numeric_limits<uint32_t>::max());

  // The default attributes_match_mask is a logical NOT of the default "DO NOT
  // CARE" attributes.
  return SetDefaultSecsAttributesMask(spec->mutable_attributes_match_mask());
}

void SetStrictMatchSpec(CodeIdentityMatchSpec *spec) {
  // Require MRENCLAVE match.
  spec->set_is_mrenclave_match_required(true);

  // Require MRSIGNER match.
  spec->set_is_mrsigner_match_required(true);

  // Require a match on all MISCSELECT bits.
  spec->set_miscselect_match_mask(std::numeric_limits<uint32_t>::max());

  // Require a match for all ATTRIBUTES bits.
  SetStrictSecsAttributesMask(spec->mutable_attributes_match_mask());
}

void SetSelfCodeIdentity(CodeIdentity *identity) {
  // The default identity is the identity of the current enclave.
  *identity = GetSelfIdentity()->identity;
}

Status SetDefaultSelfCodeIdentityExpectation(
    CodeIdentityExpectation *expectation) {
  SetSelfCodeIdentity(expectation->mutable_reference_identity());
  return SetDefaultMatchSpec(expectation->mutable_match_spec());
}

Status SetStrictSelfCodeIdentityExpectation(
    CodeIdentityExpectation *expectation) {
  CodeIdentityMatchSpec match_spec;
  SetStrictMatchSpec(&match_spec);

  CodeIdentity self_identity;
  SetSelfCodeIdentity(&self_identity);

  return SetExpectation(match_spec, self_identity, expectation);
}

Status ParseSgxIdentity(const EnclaveIdentity &generic_identity,
                        CodeIdentity *sgx_identity) {
  const EnclaveIdentityDescription &description =
      generic_identity.description();
  if (description.identity_type() != CODE_IDENTITY) {
    return Status(
        ::asylo::error::GoogleError::INVALID_ARGUMENT,
        ::absl::StrCat(
            "Invalid identity_type: Expected = CODE_IDENTITY, Actual = ",
            EnclaveIdentityType_Name(description.identity_type())));
  }
  if (description.authority_type() != kSgxAuthorizationAuthority) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  ::absl::StrCat("Invalid authority_type: Expected = ",
                                 kSgxAuthorizationAuthority,
                                 ", Actual = ", description.authority_type()));
  }
  if (!sgx_identity->ParseFromString(generic_identity.identity())) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Could not parse SGX identity from the identity string");
  }
  if (!IsValidCodeIdentity(*sgx_identity)) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Parsed SGX identity is invalid");
  }
  return Status::OkStatus();
}

Status ParseSgxMatchSpec(const std::string &generic_match_spec,
                         CodeIdentityMatchSpec *sgx_match_spec) {
  if (!sgx_match_spec->ParseFromString(generic_match_spec)) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Could not parse SGX match spec from the match-spec string");
  }
  if (!IsValidMatchSpec(*sgx_match_spec)) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Parsed SGX match spec is invalid");
  }
  return Status::OkStatus();
}

Status ParseSgxExpectation(
    const EnclaveIdentityExpectation &generic_expectation,
    CodeIdentityExpectation *sgx_expectation) {
  // First, parse the identity portion of the expectation, as that also
  // verifies whether the expectation is of correct type.
  ASYLO_RETURN_IF_ERROR(
      ParseSgxIdentity(generic_expectation.reference_identity(),
                       sgx_expectation->mutable_reference_identity()));
  ASYLO_RETURN_IF_ERROR(ParseSgxMatchSpec(
      generic_expectation.match_spec(), sgx_expectation->mutable_match_spec()));
  if (!internal::IsIdentityCompatibleWithMatchSpec(
          sgx_expectation->reference_identity(),
          sgx_expectation->match_spec())) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Parsed SGX expectation is invalid");
  }
  return Status::OkStatus();
}

Status SerializeSgxIdentity(const CodeIdentity &sgx_identity,
                            EnclaveIdentity *generic_identity) {
  if (!IsValidCodeIdentity(sgx_identity)) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Invalid sgx_identity parameter");
  }
  SetSgxIdentityDescription(generic_identity->mutable_description());
  if (!sgx_identity.SerializeToString(generic_identity->mutable_identity())) {
    return Status(::asylo::error::GoogleError::INTERNAL,
                  "Could not serialize SGX identity to a string");
  }
  return Status::OkStatus();
}

Status SerializeSgxMatchSpec(const CodeIdentityMatchSpec &sgx_match_spec,
                             std::string *generic_match_spec) {
  if (!IsValidMatchSpec(sgx_match_spec)) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Invalid sgx_match_spec parameter");
  }
  if (!sgx_match_spec.SerializeToString(generic_match_spec)) {
    return Status(::asylo::error::GoogleError::INTERNAL,
                  "Could not serialize SGX match spec to a string");
  }
  return Status::OkStatus();
}

Status SerializeSgxExpectation(
    const CodeIdentityExpectation &sgx_expectation,
    EnclaveIdentityExpectation *generic_expectation) {
  ASYLO_RETURN_IF_ERROR(
      SerializeSgxIdentity(sgx_expectation.reference_identity(),
                           generic_expectation->mutable_reference_identity()));
  return SerializeSgxMatchSpec(sgx_expectation.match_spec(),
                               generic_expectation->mutable_match_spec());
}

void SetTargetinfoFromSelfIdentity(Targetinfo *tinfo) {
  const SelfIdentity *self_identity = GetSelfIdentity();
  tinfo->measurement = self_identity->mrenclave;
  tinfo->attributes = self_identity->attributes;
  tinfo->miscselect = self_identity->miscselect;
  tinfo->reserved1.fill(0);
  tinfo->reserved2.fill(0);
}

Status VerifyHardwareReport(const Report &report) {
  AlignedHardwareKeyPtr report_key;

  ASYLO_RETURN_IF_ERROR(GetReportKey(report.keyid, report_key.get()));

  // Compute the report MAC. SGX uses CMAC to MAC the contents of the report.
  // The last two fields (KEYID and MAC) from the REPORT struct are not
  // included in the MAC computation.
  constexpr size_t kReportMacSize = sizeof(report.mac);
  static_assert(kReportMacSize == AES_BLOCK_SIZE,
                "Size of the mac field in the REPORT structure is incorrect.");
  SafeBytes<kReportMacSize> actual_mac;
  if (AES_CMAC(/*out=*/actual_mac.data(), /*key=*/report_key->data(),
               /*key_len=*/report_key->size(),
               /*in=*/reinterpret_cast<const uint8_t *>(&report),
               /*in_len=*/offsetof(Report, keyid)) != 1) {
    return Status(
        error::GoogleError::INTERNAL,
        absl::StrCat("CMAC computation failed: ", BsslLastErrorString()));
  }

  // Inequality operator on a SafeBytes object performs a constant-time
  // comparison, which is required for MAC verification.
  if (actual_mac != report.mac) {
    return Status(error::GoogleError::INTERNAL, "MAC verification failed");
  }
  return Status::OkStatus();
}

}  // namespace sgx
}  // namespace asylo
