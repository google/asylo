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

#include "asylo/identity/platform/sgx/sgx_identity_expectation_matcher.h"

#include "asylo/identity/descriptions.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/util/status_macros.h"

namespace asylo {

StatusOr<bool> SgxIdentityExpectationMatcher::MatchAndExplain(
    const EnclaveIdentity &identity,
    const EnclaveIdentityExpectation &expectation,
    std::string *explanation) const {
  // If this call fails, then |identity| either does not have the correct
  // description, or is malformed.
  SgxIdentity sgx_identity;
  ASYLO_RETURN_IF_ERROR(sgx::ParseSgxIdentity(identity, &sgx_identity));

  // If this call fails, then |expectation|.reference_identity() either does not
  // have the correct description, or is malformed.
  SgxIdentityExpectation sgx_identity_expectation;
  ASYLO_RETURN_IF_ERROR(
      sgx::ParseSgxExpectation(expectation, &sgx_identity_expectation));

  return sgx::MatchIdentityToExpectation(sgx_identity, sgx_identity_expectation,
                                         explanation);
}

EnclaveIdentityDescription SgxIdentityExpectationMatcher::Description() const {
  EnclaveIdentityDescription description;
  SetSgxIdentityDescription(&description);
  return description;
}

// Static registration of the SgxIdentityExpectationMatcher library.
SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(IdentityExpectationMatcherMap,
                                     SgxIdentityExpectationMatcher);

}  // namespace asylo
