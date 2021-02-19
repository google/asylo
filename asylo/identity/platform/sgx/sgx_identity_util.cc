/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/identity/platform/sgx/sgx_identity_util.h"

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/util/status_macros.h"

namespace asylo {

SgxIdentity GetSelfSgxIdentity() {
  SgxIdentity identity;
  sgx::SetSelfSgxIdentity(&identity);
  return identity;
}

StatusOr<SgxIdentityMatchSpec> CreateSgxIdentityMatchSpec(
    SgxIdentityMatchSpecOptions options) {
  SgxIdentityMatchSpec match_spec;
  switch (options) {
    case SgxIdentityMatchSpecOptions::DEFAULT:
      sgx::SetDefaultLocalSgxMatchSpec(&match_spec);
      return match_spec;
    case SgxIdentityMatchSpecOptions::STRICT_LOCAL:
      sgx::SetStrictLocalSgxMatchSpec(&match_spec);
      return match_spec;
    case SgxIdentityMatchSpecOptions::STRICT_REMOTE:
      sgx::SetStrictRemoteSgxMatchSpec(&match_spec);
      return match_spec;
  }
  return Status(absl::StatusCode::kInvalidArgument,
                absl::StrCat("Invalid MatchSpecOptions: ", options));
}

StatusOr<SgxIdentityExpectation> CreateSgxIdentityExpectation(
    SgxIdentity identity, SgxIdentityMatchSpec match_spec) {
  SgxIdentityExpectation expectation;
  *expectation.mutable_reference_identity() = std::move(identity);
  *expectation.mutable_match_spec() = std::move(match_spec);

  if (!sgx::IsValidExpectation(expectation)) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "The given SgxIdentity and SgxIdentityMatchSpec do not form "
                  "a valid expectation");
  }
  return expectation;
}

StatusOr<SgxIdentityExpectation> CreateSgxIdentityExpectation(
    SgxIdentity identity, SgxIdentityMatchSpecOptions options) {
  SgxIdentityMatchSpec match_spec;
  ASYLO_ASSIGN_OR_RETURN(match_spec, CreateSgxIdentityMatchSpec(options));
  return CreateSgxIdentityExpectation(std::move(identity),
                                      std::move(match_spec));
}

bool IsValidSgxIdentity(const SgxIdentity &identity) {
  return sgx::IsValidSgxIdentity(identity);
}

bool IsValidSgxIdentityMatchSpec(const SgxIdentityMatchSpec &match_spec) {
  return sgx::IsValidMatchSpec(match_spec);
}

bool IsValidSgxIdentityExpectation(const SgxIdentityExpectation &expectation) {
  return sgx::IsValidExpectation(expectation);
}

StatusOr<SgxIdentity> ParseSgxIdentity(
    const EnclaveIdentity &generic_identity) {
  SgxIdentity sgx_identity;
  ASYLO_RETURN_IF_ERROR(sgx::ParseSgxIdentity(generic_identity, &sgx_identity));
  return sgx_identity;
}

StatusOr<SgxIdentityMatchSpec> ParseSgxIdentityMatchSpec(
    const std::string &generic_match_spec) {
  SgxIdentityMatchSpec sgx_match_spec;
  ASYLO_RETURN_IF_ERROR(
      sgx::ParseSgxMatchSpec(generic_match_spec, &sgx_match_spec));
  return sgx_match_spec;
}

StatusOr<SgxIdentityExpectation> ParseSgxIdentityExpectation(
    const EnclaveIdentityExpectation &generic_expectation) {
  SgxIdentityExpectation sgx_expectation;
  ASYLO_RETURN_IF_ERROR(
      sgx::ParseSgxExpectation(generic_expectation, &sgx_expectation));
  return sgx_expectation;
}

StatusOr<EnclaveIdentity> SerializeSgxIdentity(
    const SgxIdentity &sgx_identity) {
  EnclaveIdentity generic_identity;
  ASYLO_RETURN_IF_ERROR(
      sgx::SerializeSgxIdentity(sgx_identity, &generic_identity));
  return generic_identity;
}

StatusOr<std::string> SerializeSgxIdentityMatchSpec(
    const SgxIdentityMatchSpec &sgx_match_spec) {
  std::string generic_match_spec;
  ASYLO_RETURN_IF_ERROR(
      sgx::SerializeSgxMatchSpec(sgx_match_spec, &generic_match_spec));
  return generic_match_spec;
}

StatusOr<EnclaveIdentityExpectation> SerializeSgxIdentityExpectation(
    const SgxIdentityExpectation &sgx_expectation) {
  EnclaveIdentityExpectation generic_expectation;
  ASYLO_RETURN_IF_ERROR(
      sgx::SerializeSgxExpectation(sgx_expectation, &generic_expectation));
  return generic_expectation;
}

}  // namespace asylo
