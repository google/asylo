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

#ifndef ASYLO_IDENTITY_DELEGATING_IDENTITY_EXPECTATION_MATCHER_H_
#define ASYLO_IDENTITY_DELEGATING_IDENTITY_EXPECTATION_MATCHER_H_

#include <string>

#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_expectation_matcher.h"
#include "asylo/util/statusor.h"

namespace asylo {

// A DelegatingIdentityExpectationMatcher delegates its MatchAndExplain() calls
// to an appropriate matcher from a program-wide static map of
// NamedIdentityExpectationMatchers.
//
// The MatchAndExplain() method makes sure that it is able to find a matcher
// implementation capable of handling the |identity| and the |expectation|
// parameters. If any of these matcher libraries are missing, it returns a
// non-ok status, indicating that |identity| and/or |expectation| is not
// recognized by the matcher. These checks are performed to make sure that the
// program has linked in all the necessary matcher libraries.
class DelegatingIdentityExpectationMatcher final
    : public IdentityExpectationMatcher {
 public:
  // From the IdentityExpectationMatcher interface.
  StatusOr<bool> MatchAndExplain(const EnclaveIdentity &identity,
                                 const EnclaveIdentityExpectation &expectation,
                                 std::string *explanation) const override;
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_DELEGATING_IDENTITY_EXPECTATION_MATCHER_H_
