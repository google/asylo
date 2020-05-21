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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_SGX_IDENTITY_EXPECTATION_MATCHER_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_SGX_IDENTITY_EXPECTATION_MATCHER_H_

#include <string>

#include "asylo/identity/identity.pb.h"
#include "asylo/identity/named_identity_expectation_matcher.h"
#include "asylo/util/statusor.h"

namespace asylo {

/// `SgxIdentityExpectationMatcher` is capable of matching SGX identities with
/// SGX identity expectations.
class SgxIdentityExpectationMatcher final
    : public NamedIdentityExpectationMatcher {
 public:
  SgxIdentityExpectationMatcher() = default;
  ~SgxIdentityExpectationMatcher() override = default;

  /// From the `IdentityExpectationMatcher` interface.
  ///
  /// \param identity An identity to match.
  /// \param expectation The identity expectation to match against.
  /// \param[out] explanation An explanation of why the match failed, if the
  ///                         return value was false.
  /// \return A bool indicating whether the match succeeded, or a non-OK Status
  ///         in the case of invalid arguments.
  StatusOr<bool> MatchAndExplain(const EnclaveIdentity &identity,
                                 const EnclaveIdentityExpectation &expectation,
                                 std::string *explanation) const override;

  /// From the `NamedIdentityExpectationMatcher` interface.
  ///
  /// \return A description of the enclave identities/enclave identity
  ///         expectations this matcher is able to match.
  EnclaveIdentityDescription Description() const override;
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_SGX_IDENTITY_EXPECTATION_MATCHER_H_
