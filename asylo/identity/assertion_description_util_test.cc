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

#include "asylo/identity/assertion_description_util.h"

#include <gtest/gtest.h>
#include "asylo/identity/identity.pb.h"
#include "asylo/test/util/proto_matchers.h"

namespace asylo {
namespace {

constexpr char kAuthority1[] = "Foo Authority";
constexpr char kAuthority2[] = "Bar Authority";

AssertionDescription MakeAssertionDescription(EnclaveIdentityType identity_type,
                                              std::string authority_type) {
  AssertionDescription description;
  description.set_identity_type(identity_type);
  description.set_authority_type(std::move(authority_type));
  return description;
}

// Verifies that the equality functor returns true for assertion descriptions
// that are equal.
TEST(AssertionDescriptionUtilTest, EqualityFunctorPositive) {
  AssertionDescription description =
      MakeAssertionDescription(EnclaveIdentityType::CODE_IDENTITY, kAuthority1);
  EXPECT_TRUE(AssertionDescriptionEq()(description, description));
}

// Verifies that the equality functor returns false for assertion descriptions
// that differ in identity type.
TEST(AssertionDescriptionUtilTest, EqualityFunctorDifferentIdentityType) {
  AssertionDescription description1 =
      MakeAssertionDescription(EnclaveIdentityType::CODE_IDENTITY, kAuthority1);
  AssertionDescription description2 =
      MakeAssertionDescription(EnclaveIdentityType::NULL_IDENTITY, kAuthority1);
  EXPECT_FALSE(AssertionDescriptionEq()(description1, description2));
}

// Verifies that the equality functor returns false for assertion descriptions
// that differ in authority type.
TEST(AssertionDescriptionUtilTest, EqualityFunctorDifferentAuthorityType) {
  AssertionDescription description1 =
      MakeAssertionDescription(EnclaveIdentityType::CODE_IDENTITY, kAuthority1);
  AssertionDescription description2 =
      MakeAssertionDescription(EnclaveIdentityType::CODE_IDENTITY, kAuthority2);
  EXPECT_FALSE(AssertionDescriptionEq()(description1, description2));
}

// Verifies that AssertionDescriptionHashSet, an absl::flat_hash_set that uses
// AssertionDescriptionHasher and AssertionDescriptionEq, works correctly.
TEST(AssertionDescriptionUtilTest, UnorderedSet) {
  AssertionDescription description1 =
      MakeAssertionDescription(EnclaveIdentityType::CODE_IDENTITY, kAuthority1);
  AssertionDescription description2 =
      MakeAssertionDescription(EnclaveIdentityType::CODE_IDENTITY, kAuthority2);
  AssertionDescription description3 =
      MakeAssertionDescription(EnclaveIdentityType::NULL_IDENTITY, kAuthority2);

  AssertionDescriptionHashSet assertion_descriptions;

  ASSERT_TRUE(assertion_descriptions.insert(description1).second);
  EXPECT_FALSE(assertion_descriptions.insert(description1).second);

  ASSERT_TRUE(assertion_descriptions.insert(description2).second);
  EXPECT_FALSE(assertion_descriptions.insert(description2).second);

  auto iter = assertion_descriptions.find(description1);
  ASSERT_NE(iter, assertion_descriptions.end());
  EXPECT_THAT(*iter, EqualsProto(description1));

  iter = assertion_descriptions.find(description2);
  ASSERT_NE(iter, assertion_descriptions.end());
  EXPECT_THAT(*iter, EqualsProto(description2));

  iter = assertion_descriptions.find(description3);
  EXPECT_EQ(iter, assertion_descriptions.end());
}

}  // namespace
}  // namespace asylo
