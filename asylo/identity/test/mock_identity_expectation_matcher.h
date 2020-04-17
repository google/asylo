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

#ifndef ASYLO_IDENTITY_TEST_MOCK_IDENTITY_EXPECTATION_MATCHER_H_
#define ASYLO_IDENTITY_TEST_MOCK_IDENTITY_EXPECTATION_MATCHER_H_

#include <gmock/gmock.h>
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_expectation_matcher.h"
#include "asylo/util/statusor.h"

namespace asylo {

class MockIdentityExpectationMatcher : public IdentityExpectationMatcher {
 public:
  MOCK_METHOD(StatusOr<bool>, MatchAndExplain,
              (const EnclaveIdentity &identity,
               const EnclaveIdentityExpectation &expectation,
               std::string *explanation),
              (const));
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_TEST_MOCK_IDENTITY_EXPECTATION_MATCHER_H_
