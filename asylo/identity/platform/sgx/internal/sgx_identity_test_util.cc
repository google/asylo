/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/identity/platform/sgx/internal/sgx_identity_test_util.h"

#include "absl/status/status.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/code_identity_constants.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace {

constexpr char kInvalidAuthorityType[] = "INVALID_AUTHORITY";
constexpr char kInvalidString[] = "Invalid String";

// Randomly selects an element from the input vector with uniform distribution.
template <typename T>
const T RandomSelect(const std::vector<T> &choices) {
  size_t rand_val = TrivialRandomObject<size_t>();
  if (choices.empty()) {
    LOG(FATAL) << "Choices must have a non-zero size";
  }
  return choices[rand_val % choices.size()];
}

template <typename T>
const T RandomSelect(std::initializer_list<T> initializer) {
  return RandomSelect(std::vector<T>(initializer));
}

// Returns true with a |percent| / 100 probability.
bool ShouldFuzzField(int percent) {
  // Use a 64-bit number to minimize skewing the result to lower values.
  uint64_t rand = TrivialRandomObject<uint64_t>();
  rand %= 100;
  return rand < percent;
}

// A pointer to a ProtoT member method that sets a field of type FieldT.
template <typename ProtoT, typename FieldT>
using ProtoFieldSetter = void (ProtoT::*)(FieldT);

// The following two helper functions fuzz the field referred to by the
// |set_field| method in |message| with a |percent| / 100 probability.
template <typename ProtoT, typename FieldT>
void FuzzField(int percent, ProtoFieldSetter<ProtoT, FieldT> set_field,
               ProtoT *message) {
  if (ShouldFuzzField(percent)) {
    (message->*set_field)(TrivialRandomObject<FieldT>());
  }
}

template <typename ProtoT>
void FuzzField(int percent, ProtoFieldSetter<ProtoT, bool> set_field,
               ProtoT *message) {
  // Don't use TrivialRandomObject() to set a bool to a random value because not
  // all byte values are valid for bool. Instead, just set the value of the bool
  // based on the first bit of a random number.
  if (ShouldFuzzField(percent)) {
    if (TrivialRandomObject<uint8_t>() & 0x1) {
      (message->*set_field)(true);
    } else {
      (message->*set_field)(false);
    }
  }
}

// Generates and returns a random Attributes, where each field is randomly
// filled with a |percent|% chance.
Attributes GetRandomAttributes(int percent = 100) {
  Attributes attributes;
  FuzzField(percent, &Attributes::set_flags, &attributes);
  FuzzField(percent, &Attributes::set_xfrm, &attributes);
  return attributes;
}

// Generates and returns a random CodeIdentityMatchSpec, where each field is
// randomly filled with a |percent|% chance.
CodeIdentityMatchSpec GetRandomMatchSpec(int percent = 100) {
  CodeIdentityMatchSpec spec;
  FuzzField(percent, &CodeIdentityMatchSpec::set_is_mrenclave_match_required,
            &spec);
  FuzzField(percent, &CodeIdentityMatchSpec::set_is_mrsigner_match_required,
            &spec);
  FuzzField(percent, &CodeIdentityMatchSpec::set_miscselect_match_mask, &spec);
  *spec.mutable_attributes_match_mask() = GetRandomAttributes(percent);
  return spec;
}

// Generates and returns a random MachineConfigurationMatchSpec, where each
// field is randomly set with a |percent|% chance.
MachineConfigurationMatchSpec GetRandomSgxMachineConfigurationMatchSpec(
    int percent = 100) {
  MachineConfigurationMatchSpec spec;
  FuzzField(percent,
            &MachineConfigurationMatchSpec::set_is_cpu_svn_match_required,
            &spec);
  FuzzField(percent,
            &MachineConfigurationMatchSpec::set_is_sgx_type_match_required,
            &spec);
  return spec;
}

// Generates and returns a random SgxIdentityMatchSpec, where each field is
// randomly set with a |percent|% chance.
SgxIdentityMatchSpec GetRandomSgxIdentityMatchSpec(int percent = 100) {
  SgxIdentityMatchSpec spec;
  *spec.mutable_code_identity_match_spec() = GetRandomMatchSpec(percent);
  *spec.mutable_machine_configuration_match_spec() =
      GetRandomSgxMachineConfigurationMatchSpec(percent);
  return spec;
}

}  // namespace

CodeIdentity GetRandomValidCodeIdentityWithConstraints(
    const std::vector<bool> &mrenclave_constraint,
    const std::vector<bool> &mrsigner_constraint) {
  CodeIdentity id;
  if (RandomSelect(mrenclave_constraint)) {
    auto hash = TrivialRandomObject<UnsafeBytes<kSha256DigestLength>>();
    id.mutable_mrenclave()->set_hash(hash.data(), hash.size());
  }

  if (RandomSelect(mrsigner_constraint)) {
    auto hash = TrivialRandomObject<UnsafeBytes<kSha256DigestLength>>();
    id.mutable_signer_assigned_identity()->mutable_mrsigner()->set_hash(
        hash.data(), hash.size());
  }
  id.mutable_signer_assigned_identity()->set_isvprodid(
      TrivialRandomObject<uint16_t>());
  id.mutable_signer_assigned_identity()->set_isvsvn(
      TrivialRandomObject<uint16_t>());
  *id.mutable_attributes() = GetRandomAttributes();
  id.set_miscselect(TrivialRandomObject<uint32_t>());
  return id;
}

CodeIdentity GetRandomValidCodeIdentity() {
  std::vector<bool> mr_selection_choices{true, false};
  return GetRandomValidCodeIdentityWithConstraints(mr_selection_choices,
                                                   mr_selection_choices);
}

CodeIdentityMatchSpec GetRandomValidMatchSpec() {
  // Get a random match spec with all fields populated.
  return GetRandomMatchSpec();
}

SgxIdentity GetRandomValidSgxIdentityWithConstraints(
    const std::vector<bool> &mrenclave_constraint,
    const std::vector<bool> &mrsigner_constraint,
    const std::vector<bool> &cpu_svn_constraint,
    const std::vector<bool> &sgx_type_constraint) {
  SgxIdentity sgx_id;
  *sgx_id.mutable_code_identity() = GetRandomValidCodeIdentityWithConstraints(
      mrenclave_constraint, mrsigner_constraint);
  if (RandomSelect(cpu_svn_constraint)) {
    auto cpusvn = TrivialRandomObject<UnsafeBytes<16>>();
    sgx_id.mutable_machine_configuration()->mutable_cpu_svn()->set_value(
        cpusvn.data(), cpusvn.size());
  }

  if (RandomSelect(sgx_type_constraint)) {
    sgx_id.mutable_machine_configuration()->set_sgx_type(
        RandomSelect({SgxType::STANDARD}));
  }

  return sgx_id;
}

SgxIdentity GetRandomValidSgxIdentity() {
  std::vector<bool> constraint{true, false};
  return GetRandomValidSgxIdentityWithConstraints(constraint, constraint,
                                                  constraint, constraint);
}

SgxIdentityMatchSpec GetRandomValidSgxMatchSpec() {
  SgxIdentityMatchSpec spec;
  *spec.mutable_code_identity_match_spec() = GetRandomMatchSpec();
  *spec.mutable_machine_configuration_match_spec() =
      GetRandomSgxMachineConfigurationMatchSpec();
  return spec;
}

SgxIdentityExpectation GetRandomValidSgxExpectation() {
  SgxIdentityExpectation expectation;
  *expectation.mutable_match_spec() = GetRandomValidSgxMatchSpec();
  std::vector<bool> mrenclave_constraint{expectation.match_spec()
                                             .code_identity_match_spec()
                                             .is_mrenclave_match_required()};
  std::vector<bool> mrsigner_constraint{expectation.match_spec()
                                            .code_identity_match_spec()
                                            .is_mrsigner_match_required()};
  std::vector<bool> cpu_svn_constraint{expectation.match_spec()
                                           .machine_configuration_match_spec()
                                           .is_cpu_svn_match_required()};
  std::vector<bool> sgx_type_constraint{expectation.match_spec()
                                            .machine_configuration_match_spec()
                                            .is_sgx_type_match_required()};
  *expectation.mutable_reference_identity() =
      GetRandomValidSgxIdentityWithConstraints(
          mrenclave_constraint, mrsigner_constraint, cpu_svn_constraint,
          sgx_type_constraint);
  return expectation;
}

Status SetRandomValidGenericIdentity(EnclaveIdentity *generic_identity,
                                     SgxIdentity *corresponding_sgx_identity) {
  SetSgxIdentityDescription(generic_identity->mutable_description());
  *generic_identity->mutable_version() = kSgxIdentityVersionString;

  *corresponding_sgx_identity->mutable_machine_configuration() =
      MachineConfiguration::default_instance();

  SgxIdentity sgx_identity = GetRandomValidSgxIdentity();
  if (!sgx_identity.SerializeToString(generic_identity->mutable_identity())) {
    return absl::InvalidArgumentError("Failed to serialize SgxIdentity");
  }
  *corresponding_sgx_identity = sgx_identity;
  return absl::OkStatus();
}

Status SetRandomInvalidGenericIdentity(EnclaveIdentity *generic_identity) {
  bool is_valid = true;
  while (is_valid) {
    EnclaveIdentityType identity_type = RandomSelect(
        {UNKNOWN_IDENTITY, NULL_IDENTITY, CODE_IDENTITY, CERT_IDENTITY});
    generic_identity->mutable_description()->set_identity_type(identity_type);
    is_valid &= (identity_type == CODE_IDENTITY);

    std::string authority_type =
        RandomSelect({kSgxAuthorizationAuthority, kInvalidAuthorityType});
    generic_identity->mutable_description()->set_authority_type(authority_type);
    is_valid &= (authority_type == kSgxAuthorizationAuthority);

    std::string version_string =
        RandomSelect({kSgxIdentityVersionString, kInvalidString});
    generic_identity->set_version(version_string);
    is_valid &= (version_string == kSgxIdentityVersionString);

    std::string empty_sgx_code_identity_string;
    if (!SgxIdentity::default_instance().SerializeToString(
            &empty_sgx_code_identity_string)) {
      return absl::InvalidArgumentError(
          "Failed to serialize empty SgxIdentity");
    }

    std::string valid_identity_string;
    if (!GetRandomValidSgxIdentity().SerializeToString(
            &valid_identity_string)) {
      return absl::InvalidArgumentError(
          "Failed to serialize valid SgxIdentity");
    }

    std::string identity_string = RandomSelect(std::vector<std::string>{
        kInvalidString, empty_sgx_code_identity_string, valid_identity_string});

    generic_identity->set_identity(identity_string);
    is_valid &= (identity_string == valid_identity_string);
  }
  return absl::OkStatus();
}

Status SetRandomValidGenericMatchSpec(
    std::string *generic_spec, SgxIdentityMatchSpec *corresponding_sgx_spec) {
  SgxIdentityMatchSpec spec = GetRandomValidSgxMatchSpec();
  if (!spec.SerializeToString(generic_spec)) {
    return absl::InvalidArgumentError(
        "Failed to serialize CodeIdentityMatchSpec");
  }
  *corresponding_sgx_spec = spec;
  return absl::OkStatus();
}

Status SetRandomInvalidGenericMatchSpec(std::string *generic_spec) {
  SgxIdentityMatchSpec spec;

  for (int count = 0; count < 100; count++) {
    spec.Clear();
    spec = GetRandomSgxIdentityMatchSpec(/*percent=*/75);
    // A spec is valid if and only if all four fields in the spec are set.
    // Thus, in each iteration, the probability that a valid spec is produced
    // is 0.25. Consequently, the probability that count will reach 100 is
    // (0.25)^100, or 2^-200.
    if (!IsValidMatchSpec(spec)) {
      spec.SerializeToString(generic_spec);
      return absl::OkStatus();
    }
  }
  return absl::InternalError("Exceeded max attempts");
}

Status SetRandomValidGenericExpectation(
    EnclaveIdentityExpectation *generic_expectation,
    SgxIdentityExpectation *corresponding_sgx_expectation) {
  SgxIdentity sgx_identity;
  SgxIdentityMatchSpec sgx_spec;

  for (int count = 0; count < 100; count++) {
    ASYLO_RETURN_IF_ERROR(SetRandomValidGenericIdentity(
        generic_expectation->mutable_reference_identity(), &sgx_identity));
    ASYLO_RETURN_IF_ERROR(SetRandomValidGenericMatchSpec(
        generic_expectation->mutable_match_spec(), &sgx_spec));
    ASYLO_RETURN_IF_ERROR(
        SetExpectation(sgx_spec, sgx_identity, corresponding_sgx_expectation));
    if (IsValidExpectation(*corresponding_sgx_expectation)) {
      return absl::OkStatus();
    }
  }
  return absl::InternalError("Exceeded max attempts");
}

Status SetRandomInvalidGenericExpectation(
    EnclaveIdentityExpectation *generic_expectation) {
  SgxIdentity sgx_identity;
  SgxIdentityMatchSpec sgx_spec;
  SgxIdentityExpectation expectation;
  std::vector<bool> validity_choices{true, false};

  for (int count = 0; count < 100; count++) {
    if (RandomSelect(validity_choices)) {
      ASYLO_RETURN_IF_ERROR(SetRandomValidGenericIdentity(
          generic_expectation->mutable_reference_identity(), &sgx_identity));
    } else {
      ASYLO_RETURN_IF_ERROR(SetRandomInvalidGenericIdentity(
          generic_expectation->mutable_reference_identity()));
    }
    if (RandomSelect(validity_choices)) {
      ASYLO_RETURN_IF_ERROR(SetRandomValidGenericMatchSpec(
          generic_expectation->mutable_match_spec(), &sgx_spec));
    } else {
      ASYLO_RETURN_IF_ERROR(SetRandomInvalidGenericMatchSpec(
          generic_expectation->mutable_match_spec()));
    }

    *expectation.mutable_reference_identity() = sgx_identity;
    *expectation.mutable_match_spec() = sgx_spec;

    if (!IsValidExpectation(expectation)) {
      return absl::OkStatus();
    }
  }
  return absl::InternalError("Exceeded max attempts");
}

}  // namespace sgx
}  // namespace asylo
