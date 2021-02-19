/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/identity/init.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/identity/attestation/enclave_assertion_generator.h"
#include "asylo/identity/attestation/enclave_assertion_verifier.h"
#include "asylo/identity/enclave_assertion_authority.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/init_internal.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {

Status InitializeEnclaveAssertionVerifier(
    const EnclaveAssertionAuthorityConfig &config) {
  const AssertionDescription &description = config.description();
  std::string authority_id;
  ASYLO_ASSIGN_OR_RETURN(
      authority_id,
      EnclaveAssertionAuthority::GenerateAuthorityId(
          description.identity_type(), description.authority_type()));

  auto verifier_it = AssertionVerifierMap::GetValue(authority_id);
  if (verifier_it == AssertionVerifierMap::value_end()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Config for ", description.ShortDebugString(),
                     " does not match any known assertion verifier"));
  }
  return internal::TryInitialize(config.config(), verifier_it);
}

Status InitializeEnclaveAssertionGenerator(
    const EnclaveAssertionAuthorityConfig &config) {
  const AssertionDescription &description = config.description();
  std::string authority_id;
  ASYLO_ASSIGN_OR_RETURN(
      authority_id,
      EnclaveAssertionAuthority::GenerateAuthorityId(
          description.identity_type(), description.authority_type()));

  auto generator_it = AssertionGeneratorMap::GetValue(authority_id);
  if (generator_it == AssertionGeneratorMap::value_end()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Config for ", description.ShortDebugString(),
                     " does not match any known assertion verifier"));
  }
  return internal::TryInitialize(config.config(), generator_it);
}

}  // namespace asylo
