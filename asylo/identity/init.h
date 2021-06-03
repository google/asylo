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

#ifndef ASYLO_IDENTITY_INIT_H_
#define ASYLO_IDENTITY_INIT_H_

#include <string>

#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/identity/attestation/enclave_assertion_generator.h"
#include "asylo/identity/attestation/enclave_assertion_verifier.h"
#include "asylo/identity/enclave_assertion_authority.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/init_internal.h"
#include "asylo/util/status.h"

namespace asylo {

// Initializes an EnclaveAssertionVerifier that has been statically-registered
// into the program static maps using |config|. Each authority will be
// initialized at most once between all calls to this function or
// |InitializeEnclaveAssertionAuthorities|.
//
// This function will return a non-ok status if any of the following occurs:
//   * |config| does not have a matching EnclaveAssertionVerifier
//   * The verifier could not be initialized with |config|
//   * The authority identifier could not be generated from |config|
Status InitializeEnclaveAssertionVerifier(
    const EnclaveAssertionAuthorityConfig &config);

// Initializes an EnclaveAssertionGenerator that has been statically-registered
// into the program static maps using |config|. Each authority will be
// initialized at most once between all calls to this function or
// |InitializeEnclaveAssertionAuthorities|.
//
// This function will return a non-ok status if any of the following occurs:
//   * |config| does not have a matching EnclaveAssertionGenerator
//   * The generator could not be initialized with |config|
//   * The authority identifier could not be generated from |config|
Status InitializeEnclaveAssertionGenerator(
    const EnclaveAssertionAuthorityConfig &config);

// Initializes EnclaveAssertionGenerators and EnclaveAssertionVerifiers that
// have been statically-registered into the program static maps using the
// configs provided in the range [|configs_begin|, |configs_end|). If a config
// is not available for an authority, does not attempt to initialize that
// authority. Each authority will be initialized at most once between all calls
// to this function and |InitializeEnclaveAssertionGenerator| and
// |InitializeEnclaveAssertionVerifier|.
//
// ConfigIteratorT must be an iterator type that satisfies the following
// constraints:
//   * It provides a dereference operator, which returns an immutable reference
//     to type EnclaveAssertionAuthorityConfig
//   * It provides a prefix increment operator
//   * It provides an equality operator for comparisons with ConfigIteratorT
//
// This function will return a non-ok status if any of the following occurs:
//   * A config was provided for which there is no matching
//     EnclaveAssertionGenerator and/or EnclaveAssertionVerifier
//   * An authority could not be initialized with a provided config
//   * An authority identifier could not be generated from a provided config
//
// Note that if this method has already been called successfully, future calls
// will have no effect.
template <class ConfigIteratorT>
Status InitializeEnclaveAssertionAuthorities(ConfigIteratorT configs_begin,
                                             ConfigIteratorT configs_end) {
  bool ok = true;

  // Initialize assertion authorities with provided configs.
  for (auto it = configs_begin; it != configs_end; ++it) {
    const EnclaveAssertionAuthorityConfig &config = *it;

    const AssertionDescription &description = config.description();
    StatusOr<std::string> authority_id_result =
        EnclaveAssertionAuthority::GenerateAuthorityId(
            description.identity_type(), description.authority_type());
    if (!authority_id_result.ok()) {
      ok = false;
      LOG(ERROR) << authority_id_result.status();
      continue;
    }

    std::string authority_id = authority_id_result.value();

    auto generator_it = AssertionGeneratorMap::GetValue(authority_id);
    if (generator_it != AssertionGeneratorMap::value_end()) {
      if (!internal::TryInitialize(config.config(), generator_it).ok()) {
        ok = false;
      }
    } else {
      ok = false;
      LOG(WARNING) << "Config for " << description.ShortDebugString()
                   << " does not match any known assertion generator";
    }

    auto verifier_it = AssertionVerifierMap::GetValue(authority_id);
    if (verifier_it != AssertionVerifierMap::value_end()) {
      if (!internal::TryInitialize(config.config(), verifier_it).ok()) {
        ok = false;
      }
    } else {
      ok = false;
      LOG(WARNING) << "Config for " << description.ShortDebugString()
                   << " does not match any known assertion verifier";
    }
  }

  return ok ? absl::OkStatus()
            : absl::InvalidArgumentError(
                  "One or more errors occurred while attempting to initialize "
                  "assertion generators and assertion verifiers");
}

}  // namespace asylo

#endif  // ASYLO_IDENTITY_INIT_H_
