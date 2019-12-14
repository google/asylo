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

#include "asylo/identity/attestation/null/null_identity_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/identity/attestation/null/internal/null_identity_constants.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"

namespace asylo {
namespace {

bool IsNullIdentityDescription(
    const EnclaveIdentityDescription &identity_description) {
  return identity_description.identity_type() ==
             EnclaveIdentityType::NULL_IDENTITY &&
         identity_description.authority_type() == kNullAuthorizationAuthority;
}

TEST(NullIdentityUtilTest, SetNullIdentityDescription) {
  EnclaveIdentityDescription description;
  SetNullIdentityDescription(&description);

  EXPECT_TRUE(IsNullIdentityDescription(description));
}

TEST(NullIdentityUtilTest, SetNullAssertionDescription) {
  AssertionDescription description;
  SetNullAssertionDescription(&description);

  EXPECT_EQ(description.identity_type(), NULL_IDENTITY);
  EXPECT_EQ(description.authority_type(), kNullAssertionAuthority);
}

TEST(NullIdentityUtilTest, SetNullIdentityExpectation) {
  EnclaveIdentityExpectation expectation = CreateNullIdentityExpectation();

  EXPECT_TRUE(IsNullIdentityDescription(
      expectation.reference_identity().description()));
  EXPECT_EQ(expectation.reference_identity().identity(), kNullIdentity);
  EXPECT_EQ(expectation.match_spec(), "");
}

}  // namespace
}  // namespace asylo
