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

#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"

#include <openssl/cmac.h>

#include <limits>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/crypto/sha256_hash_util.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/identity/platform/sgx/attributes_util.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/proto_format.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/identity/platform/sgx/internal/self_identity.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

std::string FormatProtoWithoutNewlines(const google::protobuf::Message &message) {
  return absl::StrReplaceAll(FormatProto(message), {{"\n", " "}});
}

// Returns a new string containing |explanations| appended to |current|.
std::string WithAppendedExplanations(
    absl::string_view current, const std::vector<std::string> &explanations) {
  if (explanations.empty()) {
    return std::string(current);
  }
  return absl::StrCat(current, " and ", absl::StrJoin(explanations, " and "));
}

// Retrieves the report key associated with |keyid| for the current enclave and
// writes it to |key|.
StatusOr<HardwareKey> GetReportKey(
    const UnsafeBytes<kKeyrequestKeyidSize> &keyid) {
  // Set KEYREQUEST to request the REPORT_KEY with the KEYID value specified in
  // the report to be verified.
  AlignedKeyrequestPtr request;

  // Zero-out the KEYREQUEST. SGX hardware requires that the reserved fields of
  // KEYREQUEST be set to zero.
  *request = TrivialZeroObject<Keyrequest>();

  request->keyname = KeyrequestKeyname::REPORT_KEY;
  request->keyid = keyid;

  // The following fields of KEYREQUEST are ignored by the SGX hardware. These
  // are just initialized to some sensible values.
  request->keypolicy = kKeypolicyMrenclaveBitMask;
  request->isvsvn = 0;
  request->cpusvn.fill(0);
  request->attributemask.Clear();
  request->miscmask = 0;

  return HardwareInterface::CreateDefault()->GetKey(*request);
}

StatusOr<bool> MatchIdentityToExpectation(const CodeIdentity &identity,
                                          const CodeIdentity &expected,
                                          const CodeIdentityMatchSpec &spec,
                                          std::string *explanation) {
  std::vector<std::string> explanations;

  if (spec.is_mrenclave_match_required() &&
      identity.mrenclave() != expected.mrenclave()) {
    explanations.emplace_back(absl::StrFormat(
        "MRENCLAVE value %s does not match expected MRENCLAVE value %s",
        absl::BytesToHexString(
            MakeView<absl::string_view>(identity.mrenclave().hash())),
        absl::BytesToHexString(
            MakeView<absl::string_view>(expected.mrenclave().hash()))));
  }

  const SignerAssignedIdentity &given_id = identity.signer_assigned_identity();
  const SignerAssignedIdentity &expected_id =
      expected.signer_assigned_identity();

  if (spec.is_mrsigner_match_required() &&
      given_id.mrsigner() != expected_id.mrsigner()) {
    explanations.emplace_back(absl::StrFormat(
        "MRSIGNER value %s does not match expected MRSIGNER value %s",
        absl::BytesToHexString(
            MakeView<absl::string_view>(given_id.mrsigner().hash())),
        absl::BytesToHexString(
            MakeView<absl::string_view>(expected_id.mrsigner().hash()))));
  }

  if (given_id.isvprodid() != expected_id.isvprodid()) {
    explanations.emplace_back(absl::StrFormat(
        "ISVPRODID value %d does not match expected ISVPRODID value %d",
        given_id.isvprodid(), expected_id.isvprodid()));
  }
  if (given_id.isvsvn() < expected_id.isvsvn()) {
    explanations.emplace_back(absl::StrFormat(
        "ISVSVN value %d is lower than expected ISVSVN value %d",
        given_id.isvsvn(), expected_id.isvsvn()));
  }

  if ((spec.miscselect_match_mask() & identity.miscselect()) !=
      (spec.miscselect_match_mask() & expected.miscselect())) {
    explanations.emplace_back(absl::StrFormat(
        "MISCSELECT value %#08x does not match expected MISCSELECT value %#08x "
        "masked with %#08x",
        identity.miscselect(), expected.miscselect(),
        spec.miscselect_match_mask()));
  }

  if ((spec.attributes_match_mask() & identity.attributes()) !=
      (spec.attributes_match_mask() & expected.attributes())) {
    explanations.emplace_back(absl::StrFormat(
        "ATTRIBUTES value {%s} does not match expected ATTRIBUTES value {%s} "
        "masked with {%s}",
        FormatProtoWithoutNewlines(identity.attributes()),
        FormatProtoWithoutNewlines(expected.attributes()),
        FormatProtoWithoutNewlines(spec.attributes_match_mask())));
  }

  if (explanation != nullptr) {
    *explanation = absl::StrJoin(explanations, " and ");
  }

  // If |explanations| is non-empty, it means that one or more properties of the
  // CodeIdentity did not match the expectation.
  return explanations.empty();
}

bool IsValidMatchSpec(const CodeIdentityMatchSpec &match_spec) {
  return match_spec.has_is_mrenclave_match_required() &&
         match_spec.has_is_mrsigner_match_required() &&
         match_spec.has_miscselect_match_mask() &&
         match_spec.has_attributes_match_mask();
}

CodeIdentity ParseCodeIdentityFromHardwareReport(const ReportBody &report) {
  CodeIdentity identity;
  identity.mutable_mrenclave()->set_hash(report.mrenclave.data(),
                                         report.mrenclave.size());
  identity.mutable_signer_assigned_identity()->mutable_mrsigner()->set_hash(
      report.mrsigner.data(), report.mrsigner.size());
  identity.mutable_signer_assigned_identity()->set_isvprodid(report.isvprodid);
  identity.mutable_signer_assigned_identity()->set_isvsvn(report.isvsvn);
  *identity.mutable_attributes() = report.attributes.ToProtoAttributes();
  identity.set_miscselect(report.miscselect);
  return identity;
}

void SetDefaultCodeIdentityMatchSpec(CodeIdentityMatchSpec *spec) {
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
  *spec->mutable_attributes_match_mask() =
      SecsAttributeSet::GetDefaultMask().ToProtoAttributes();
}

void SetStrictCodeIdentityMatchSpec(CodeIdentityMatchSpec *spec) {
  // Require MRENCLAVE match.
  spec->set_is_mrenclave_match_required(true);

  // Require MRSIGNER match.
  spec->set_is_mrsigner_match_required(true);

  // Require a match on all MISCSELECT bits.
  spec->set_miscselect_match_mask(std::numeric_limits<uint32_t>::max());

  // Require a match for all ATTRIBUTES bits.
  *spec->mutable_attributes_match_mask() =
      SecsAttributeSet::GetStrictMask().ToProtoAttributes();
}

// Verifies whether |identity| is compatible with |spec|.
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

// Verifies whether |identity| is compatible with |spec|.
bool IsIdentityCompatibleWithMatchSpec(const SgxIdentity &identity,
                                       const SgxIdentityMatchSpec &spec) {
  const MachineConfiguration &machine_config = identity.machine_configuration();
  const MachineConfigurationMatchSpec &machine_config_match_spec =
      spec.machine_configuration_match_spec();

  if (machine_config_match_spec.is_cpu_svn_match_required() &&
      !machine_config.has_cpu_svn()) {
    return false;
  }
  if (machine_config_match_spec.is_sgx_type_match_required() &&
      !machine_config.has_sgx_type()) {
    return false;
  }

  return IsIdentityCompatibleWithMatchSpec(identity.code_identity(),
                                           spec.code_identity_match_spec());
}

}  // namespace

StatusOr<bool> MatchIdentityToExpectation(
    const SgxIdentity &identity, const SgxIdentityExpectation &expectation,
    std::string *explanation) {
  if (!IsValidExpectation(expectation)) {
    return Status(::absl::StatusCode::kInvalidArgument,
                  "Expectation parameter is invalid");
  }

  // We don't propagate the |is_legacy_expectation| parameter to this call
  // because we still want to be able to perform matches where "legacy state" of
  // the expectation and the identity are mismatched (resulting in a success if
  // the partial match is a success).
  if (!IsValidSgxIdentity(identity)) {
    return Status(::absl::StatusCode::kInvalidArgument,
                  "Identity parameter is invalid");
  }
  if (!IsIdentityCompatibleWithMatchSpec(identity, expectation.match_spec())) {
    return Status(::absl::StatusCode::kInvalidArgument,
                  "Identity is not compatible with specified match spec");
  }

  // Perform checks for the MachineConfiguration component of SgxIdentity.
  const MachineConfiguration &actual_config = identity.machine_configuration();
  const MachineConfiguration &expected_config =
      expectation.reference_identity().machine_configuration();
  const MachineConfigurationMatchSpec &machine_config_match_spec =
      expectation.match_spec().machine_configuration_match_spec();

  std::vector<std::string> explanations;

  if (machine_config_match_spec.is_cpu_svn_match_required() &&
      actual_config.cpu_svn().value() != expected_config.cpu_svn().value()) {
    explanations.emplace_back(absl::StrFormat(
        "CPUSVN value %s does not match expected CPUSVN value %s",
        absl::BytesToHexString(actual_config.cpu_svn().value()),
        absl::BytesToHexString(expected_config.cpu_svn().value())));
  }
  if (machine_config_match_spec.is_sgx_type_match_required() &&
      actual_config.sgx_type() != expected_config.sgx_type()) {
    explanations.emplace_back(
        absl::StrFormat("SGX Type %s does not match expected SGX Type %s",
                        ProtoEnumValueName(actual_config.sgx_type()),
                        ProtoEnumValueName(expected_config.sgx_type())));
  }

  // Perform checks for the CodeIdentity component of SgxIdentity.
  bool code_identity_match_result;
  ASYLO_ASSIGN_OR_RETURN(
      code_identity_match_result,
      MatchIdentityToExpectation(
          identity.code_identity(),
          expectation.reference_identity().code_identity(),
          expectation.match_spec().code_identity_match_spec(), explanation));

  if (explanation != nullptr) {
    *explanation = WithAppendedExplanations(*explanation, explanations);
  }

  // If |explanations| is non-empty, it means that one or more properties of the
  // SgxMachineConfiguration did not match the expectation. This value is
  // logically AND'd with the result of matching the CodeIdentity component of
  // the identity to get the final match result.
  return explanations.empty() && code_identity_match_result;
}

Status SetExpectation(const SgxIdentityMatchSpec &match_spec,
                      const SgxIdentity &identity,
                      SgxIdentityExpectation *expectation) {
  if (!IsValidMatchSpec(match_spec)) {
    return Status(::absl::StatusCode::kInvalidArgument,
                  "Match spec is invalid");
  }
  if (!IsValidSgxIdentity(identity)) {
    return Status(::absl::StatusCode::kInvalidArgument, "Identity is invalid");
  }

  *expectation->mutable_match_spec() = match_spec;
  *expectation->mutable_reference_identity() = identity;
  return absl::OkStatus();
}

bool IsValidSignerAssignedIdentity(const SignerAssignedIdentity &identity) {
  return (identity.has_isvprodid() && identity.has_isvsvn());
}

bool IsValidSgxIdentity(const SgxIdentity &identity) {
  // We cannot assume that all SgxIdentity messages will have a valid and set
  // CPUSVN, because expectations are not required to populate the CPUSVN value
  // for their reference identities.
  const MachineConfiguration &machine_config = identity.machine_configuration();
  if (machine_config.has_cpu_svn() &&
      !ValidateCpuSvn(machine_config.cpu_svn()).ok()) {
    return false;
  }

  // MRENCLAVE is optional. Only the MRSIGNER part of the signer-assigned
  // identity is optional. MISCSELECT and ATTRIBUTES are required fields.
  if (!identity.code_identity().has_signer_assigned_identity() ||
      !IsValidSignerAssignedIdentity(
          identity.code_identity().signer_assigned_identity())) {
    return false;
  }

  return identity.code_identity().has_miscselect() &&
         identity.code_identity().has_attributes();
}

bool IsValidMatchSpec(const SgxIdentityMatchSpec &match_spec) {
  const MachineConfigurationMatchSpec &machine_config_match_spec =
      match_spec.machine_configuration_match_spec();
  if (!machine_config_match_spec.has_is_cpu_svn_match_required() ||
      !machine_config_match_spec.has_is_sgx_type_match_required()) {
    return false;
  }

  return IsValidMatchSpec(match_spec.code_identity_match_spec());
}

bool IsValidExpectation(const SgxIdentityExpectation &expectation) {
  const SgxIdentityMatchSpec &spec = expectation.match_spec();
  if (!IsValidMatchSpec(spec)) {
    return false;
  }

  const SgxIdentity &identity = expectation.reference_identity();
  if (!IsValidSgxIdentity(identity)) {
    return false;
  }

  return IsIdentityCompatibleWithMatchSpec(identity, spec);
}

SgxIdentity ParseSgxIdentityFromHardwareReport(const ReportBody &report) {
  SgxIdentity identity;
  identity.mutable_machine_configuration()->mutable_cpu_svn()->set_value(
      report.cpusvn.data(), report.cpusvn.size());
  *identity.mutable_code_identity() =
      ParseCodeIdentityFromHardwareReport(report);
  return identity;
}

void SetDefaultLocalSgxMatchSpec(SgxIdentityMatchSpec *spec) {
  MachineConfigurationMatchSpec *machine_config_match_spec =
      spec->mutable_machine_configuration_match_spec();

  machine_config_match_spec->set_is_cpu_svn_match_required(false);
  machine_config_match_spec->set_is_sgx_type_match_required(false);

  SetDefaultCodeIdentityMatchSpec(spec->mutable_code_identity_match_spec());
}

void SetStrictLocalSgxMatchSpec(SgxIdentityMatchSpec *spec) {
  MachineConfigurationMatchSpec *machine_config_match_spec =
      spec->mutable_machine_configuration_match_spec();

  machine_config_match_spec->set_is_cpu_svn_match_required(true);

  // SgxMachineConfiguration fields other than CPUSVN are not present in
  // locally-attested SGX identities, and so their match isn't required even in
  // the case of a "strict" match spec.
  machine_config_match_spec->set_is_sgx_type_match_required(false);

  SetStrictCodeIdentityMatchSpec(spec->mutable_code_identity_match_spec());
}

void SetDefaultRemoteSgxMatchSpec(SgxIdentityMatchSpec *spec) {
  SetDefaultLocalSgxMatchSpec(spec);
}

void SetStrictRemoteSgxMatchSpec(SgxIdentityMatchSpec *spec) {
  MachineConfigurationMatchSpec *machine_config_match_spec =
      spec->mutable_machine_configuration_match_spec();

  machine_config_match_spec->set_is_cpu_svn_match_required(true);
  machine_config_match_spec->set_is_sgx_type_match_required(true);

  SetStrictCodeIdentityMatchSpec(spec->mutable_code_identity_match_spec());
}

void SetSelfSgxIdentity(SgxIdentity *identity) {
  *identity = GetSelfIdentity()->sgx_identity;
}

Status SetDefaultLocalSelfSgxExpectation(SgxIdentityExpectation *expectation) {
  SgxIdentityMatchSpec match_spec;
  SetDefaultLocalSgxMatchSpec(&match_spec);

  SgxIdentity self_identity;
  SetSelfSgxIdentity(&self_identity);

  return SetExpectation(match_spec, self_identity, expectation);
}

Status SetStrictLocalSelfSgxExpectation(SgxIdentityExpectation *expectation) {
  SgxIdentityMatchSpec match_spec;
  SetStrictLocalSgxMatchSpec(&match_spec);

  SgxIdentity self_identity;
  SetSelfSgxIdentity(&self_identity);

  return SetExpectation(match_spec, self_identity, expectation);
}

Status SetDefaultRemoteSelfSgxExpectation(SgxIdentityExpectation *expectation) {
  SgxIdentityMatchSpec match_spec;
  SetDefaultRemoteSgxMatchSpec(&match_spec);

  SgxIdentity self_identity;
  SetSelfSgxIdentity(&self_identity);

  return SetExpectation(match_spec, self_identity, expectation);
}

Status SetStrictRemoteSelfSgxExpectation(SgxIdentityExpectation *expectation) {
  SgxIdentityMatchSpec match_spec;
  SetStrictRemoteSgxMatchSpec(&match_spec);

  SgxIdentity self_identity;
  SetSelfSgxIdentity(&self_identity);

  return SetExpectation(match_spec, self_identity, expectation);
}

Status ParseSgxIdentity(const EnclaveIdentity &generic_identity,
                        SgxIdentity *sgx_identity) {
  if (generic_identity.version() != kSgxIdentityVersionString) {
    return absl::InvalidArgumentError(
        "Unknown identity version in EnclaveIdentity");
  }
  // Parse SgxIdentity directly from serialized |identity| (the body of this
  // block is identical to the above `ParseSgxIdentity()`, but parse into
  // |sgx_identity| rather than |sgx_identity->mutable_code_identity|).
  const EnclaveIdentityDescription &description =
      generic_identity.description();
  if (description.identity_type() != CODE_IDENTITY) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Invalid identity_type: Expected = CODE_IDENTITY, Actual = ",
        ProtoEnumValueName(description.identity_type())));
  }
  if (description.authority_type() != kSgxAuthorizationAuthority) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Invalid authority_type: Expected = ", kSgxAuthorizationAuthority,
        ", Actual = ", description.authority_type()));
  }
  if (!sgx_identity->ParseFromString(generic_identity.identity())) {
    return absl::InvalidArgumentError(
        "Could not parse SGX identity from the identity string");
  }
  if (!IsValidSgxIdentity(*sgx_identity)) {
    return absl::InvalidArgumentError("Parsed SGX identity is invalid");
  }
  return absl::OkStatus();
}

Status ParseSgxMatchSpec(const std::string &generic_match_spec,
                         SgxIdentityMatchSpec *sgx_match_spec) {
  if (!sgx_match_spec->ParseFromString(generic_match_spec)) {
    return Status(::absl::StatusCode::kInvalidArgument,
                  "Could not parse SGX match spec from the match-spec string");
  }
  if (!IsValidMatchSpec(*sgx_match_spec)) {
    return Status(::absl::StatusCode::kInvalidArgument,
                  "Parsed SGX match spec is invalid");
  }
  return absl::OkStatus();
}

Status ParseSgxExpectation(
    const EnclaveIdentityExpectation &generic_expectation,
    SgxIdentityExpectation *sgx_expectation) {
  // First, parse the identity portion of the expectation, as that also
  // verifies whether the expectation is of correct type.
  ASYLO_RETURN_IF_ERROR(
      ParseSgxIdentity(generic_expectation.reference_identity(),
                       sgx_expectation->mutable_reference_identity()));
  ASYLO_RETURN_IF_ERROR(ParseSgxMatchSpec(
      generic_expectation.match_spec(), sgx_expectation->mutable_match_spec()));
  if (!IsIdentityCompatibleWithMatchSpec(sgx_expectation->reference_identity(),
                                         sgx_expectation->match_spec())) {
    return Status(::absl::StatusCode::kInvalidArgument,
                  "Parsed SGX expectation is invalid");
  }
  return absl::OkStatus();
}

Status SerializeSgxIdentity(const SgxIdentity &sgx_identity,
                            EnclaveIdentity *generic_identity) {
  if (!IsValidSgxIdentity(sgx_identity)) {
    return Status(::absl::StatusCode::kInvalidArgument, "Invalid SgxIdentity");
  }
  SetSgxIdentityDescription(generic_identity->mutable_description());
  if (!sgx_identity.SerializeToString(generic_identity->mutable_identity())) {
    return Status(::absl::StatusCode::kInternal,
                  "Could not serialize SGX identity to a string");
  }
  // Set version string to indicate that the serialized |identity| is an
  // SgxIdentity, rather than a (legacy) CodeIdentity.
  generic_identity->set_version(kSgxIdentityVersionString);
  return absl::OkStatus();
}

Status SerializeSgxMatchSpec(const SgxIdentityMatchSpec &sgx_match_spec,
                             std::string *generic_match_spec) {
  if (!IsValidMatchSpec(sgx_match_spec)) {
    return Status(::absl::StatusCode::kInvalidArgument,
                  "Invalid SgxIdentityMatchSpec");
  }
  if (!sgx_match_spec.SerializeToString(generic_match_spec)) {
    return Status(::absl::StatusCode::kInternal,
                  "Could not serialize SgxIdentityMatchSpec to a string");
  }
  return absl::OkStatus();
}

Status SerializeSgxExpectation(
    const SgxIdentityExpectation &sgx_expectation,
    EnclaveIdentityExpectation *generic_expectation) {
  ASYLO_RETURN_IF_ERROR(
      SerializeSgxIdentity(sgx_expectation.reference_identity(),
                           generic_expectation->mutable_reference_identity()));
  return SerializeSgxMatchSpec(sgx_expectation.match_spec(),
                               generic_expectation->mutable_match_spec());
}

void SetTargetinfoFromSelfIdentity(Targetinfo *tinfo) {
  const SelfIdentity *self_identity = GetSelfIdentity();

  // Zero-out the destination.
  *tinfo = TrivialZeroObject<Targetinfo>();

  // Fill the appropriate fields based on self identity.
  tinfo->measurement = self_identity->mrenclave;
  tinfo->attributes = self_identity->attributes;
  tinfo->miscselect = self_identity->miscselect;
}

Status VerifyHardwareReport(const Report &report) {
  HardwareKey report_key;
  ASYLO_ASSIGN_OR_RETURN(report_key, GetReportKey(report.keyid));

  // Compute the report MAC. SGX uses CMAC to MAC the contents of the report.
  // The last two fields (KEYID and MAC) from the REPORT struct are not
  // included in the MAC computation.
  constexpr size_t kReportMacSize = sizeof(report.mac);
  static_assert(kReportMacSize == AES_BLOCK_SIZE,
                "Size of the mac field in the REPORT structure is incorrect.");
  SafeBytes<kReportMacSize> actual_mac;
  if (AES_CMAC(/*out=*/actual_mac.data(), /*key=*/report_key.data(),
               /*key_len=*/report_key.size(),
               /*in=*/reinterpret_cast<const uint8_t *>(&report.body),
               /*in_len=*/sizeof(report.body)) != 1) {
    return absl::InternalError(
        absl::StrCat("CMAC computation failed: ", BsslLastErrorString()));
  }

  // Inequality operator on a SafeBytes object performs a constant-time
  // comparison, which is required for MAC verification.
  if (actual_mac != report.mac) {
    return absl::InternalError("MAC verification failed");
  }
  return absl::OkStatus();
}

}  // namespace sgx
}  // namespace asylo
