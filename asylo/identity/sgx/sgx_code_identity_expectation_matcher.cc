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

#include "asylo/identity/sgx/sgx_code_identity_expectation_matcher.h"

#include "asylo/identity/sgx/code_identity_util.h"

namespace asylo {

StatusOr<bool> SgxCodeIdentityExpectationMatcher::Match(
    const EnclaveIdentity &identity,
    const EnclaveIdentityExpectation &expectation) const {
  sgx::CodeIdentity code_identity;
  Status status = sgx::ParseSgxIdentity(identity, &code_identity);
  if (!status.ok()) {
    // |identity| either does not have the correct description, or is malformed.
    return status;
  }

  sgx::CodeIdentityExpectation code_identity_expectation;
  status = sgx::ParseSgxExpectation(expectation, &code_identity_expectation);
  if (!status.ok()) {
    // |expectation|.reference_identity() either does not have the correct
    // description, or is malformed.
    return status;
  }

  return sgx::MatchIdentityToExpectation(code_identity,
                                         code_identity_expectation);
}

EnclaveIdentityDescription SgxCodeIdentityExpectationMatcher::Description()
    const {
  EnclaveIdentityDescription description;
  sgx::SetSgxIdentityDescription(&description);
  return description;
}

// Static registration of the CodeIdentityExpectationMatcher library.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(IdentityExpectationMatcherMap,
                                     SgxCodeIdentityExpectationMatcher);

}  // namespace asylo
