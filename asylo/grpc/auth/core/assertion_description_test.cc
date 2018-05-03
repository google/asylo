/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/grpc/auth/core/assertion_description.h"

#include <cstdint>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/identity/identity.pb.h"

namespace asylo {
namespace {

const int kIdentitiesTestPoolSize = 3;

const char kAuthorityType1[] = "Any";
const char kAuthorityType2[] = "SGX Local";
const char kAuthorityType3[] = "SGX Remote";

// Tests creation, population, and destruction of assertion_description and
// assertion_description_array objects. A test fixture is used to store lists of
// test data. The heap checker should be active when running this test.
class AssertionDescriptionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    identity_types_ = {
      EnclaveIdentityType::NULL_IDENTITY,
      EnclaveIdentityType::CODE_IDENTITY,
      EnclaveIdentityType::CODE_IDENTITY};

    authority_types_ = {
      kAuthorityType1,
      kAuthorityType2,
      kAuthorityType3};

    // Create and default-initialize two description objects for use in tests.
    assertion_description_init(&desc1_);
    assertion_description_init(&desc2_);

    // Create and default-initialize two array objects for use in tests.
    assertion_description_array_init(/*count=*/0, &array1_);
    assertion_description_array_init(/*count=*/0, &array2_);
  }

  void TearDown() override {
    assertion_description_free(&desc1_);
    assertion_description_free(&desc2_);

    assertion_description_array_free(&array1_);
    assertion_description_array_free(&array2_);
  }

  // Initializes |desc| using the identity type and authority type from index
  // |index| in the test data pool.
  void SetAssertionDescription(int test_pool_index,
                               assertion_description *desc) {
    assertion_description_assign(
        identity_types_[test_pool_index],
        authority_types_[test_pool_index].data(),
        authority_types_[test_pool_index].size(),
        desc);
  }

  // Checks that |expected| is the same assertion_description as |actual|.
  void CheckDescriptionEquality(const assertion_description &expected,
                                const assertion_description &actual) {
    VerifyAssertionDescription(actual,
                               expected.identity_type,
                               expected.authority_type.data,
                               expected.authority_type.size);
  }

  // Adds |num_descriptions| enclave assertion_descriptions to |array| using
  // identity types and authority types from the test data pool and verifies
  // that the correct values were added.
  void AddAndVerifyIdentities(int num_descriptions,
                              assertion_description_array *array) {
    ASSERT_LE(num_descriptions, kIdentitiesTestPoolSize);
    assertion_description_array_init(/*count=*/kIdentitiesTestPoolSize,
                                            array);
    for (int i = 0; i < kIdentitiesTestPoolSize; ++i) {
      EXPECT_TRUE(
          assertion_description_array_assign_at(
              /*index=*/i,
              static_cast<int32_t>(identity_types_[i]),
              authority_types_[i].data(),
              authority_types_[i].size(),
              array));
      VerifyAssertionDescription(/*test_pool_index=*/i, array->descriptions[i]);
    }
  }

  // Checks that |actual| contains the same assertion_descriptions in the same
  // order as |expected|.
  void CheckArrayEquality(const assertion_description_array &expected,
                          const assertion_description_array &actual) {
    ASSERT_EQ(expected.count, actual.count);
    for (size_t i = 0; i < actual.count; ++i) {
      CheckDescriptionEquality(expected.descriptions[i],
                               actual.descriptions[i]);
    }
  }

  // Verifies that |desc| is populated with the identity type and authority
  // type from index |test_pool_index| of the test data pool.
  void VerifyAssertionDescription(int test_pool_index,
                                  const assertion_description &desc) {
    VerifyAssertionDescription(
        desc,
        static_cast<int32_t>(identity_types_[test_pool_index]),
        authority_types_[test_pool_index].data(),
        authority_types_[test_pool_index].size());
  }

  // Verifies that:
  //   |desc|.identity_type         == |identity_type|
  //   |desc|.authority_type.size   == |authority_type_size|
  //   |desc|.authority_type.data   == |authority_type|
  void VerifyAssertionDescription(const assertion_description &desc,
                                  int32_t identity_type,
                                  const char *authority_type,
                                  size_t authority_type_size) {
    EXPECT_EQ(desc.identity_type, identity_type);
    EXPECT_EQ(desc.authority_type.size, authority_type_size);
    EXPECT_EQ(0, memcmp(authority_type,
                        desc.authority_type.data,
                        desc.authority_type.size));
  }

  // Pool of enclave identity types for test.
  std::vector<EnclaveIdentityType> identity_types_;

  // Pool of assertion methods for test
  std::vector<std::string> authority_types_;

  assertion_description desc1_;
  assertion_description desc2_;

  assertion_description_array array1_;
  assertion_description_array array2_;
};

// Verify that freeing an empty assertion_description does not cause any errors.
// This also covers the case where an assertion_description is freed more than
// once, because AssertionDescriptionTest::TearDown will also free the
// description object used in this test.
TEST_F(AssertionDescriptionTest, FreeEmptyAssertionDescription) {
  assertion_description_free(&desc1_);
}

// Verify that populating an assertion_description is working correctly.
TEST_F(AssertionDescriptionTest, PopulateAssertionDescription) {
  // Assign to a default-initialized description.
  SetAssertionDescription(/*test_pool_index=*/0, &desc1_);
  VerifyAssertionDescription(/*test_pool_index=*/0, desc1_);

  // Overwrite a populated description.
  SetAssertionDescription(/*test_pool_index=*/1, &desc1_);
  VerifyAssertionDescription(/*test_pool_index=*/1, desc1_);
}

// Verify that copying an assertion_description to an empty description is
// working correctly.
TEST_F(AssertionDescriptionTest, CopyAssertionDescriptionEmptyDest) {
  SetAssertionDescription(/*test_pool_index=*/0, &desc1_);
  assertion_description_copy(/*src=*/&desc1_, /*dest=*/&desc2_);
  CheckDescriptionEquality(desc1_, desc2_);
}

// Verify that copying an assertion_description to a populated description is
// working correctly.
TEST_F(AssertionDescriptionTest, CopyAssertionDescriptionPopulatedDest) {
  SetAssertionDescription(/*test_pool_index=*/0, &desc1_);
  SetAssertionDescription(/*test_pool_index=*/1, &desc2_);

  assertion_description_copy(/*src=*/&desc1_, /*dest=*/&desc2_);
  CheckDescriptionEquality(desc1_, desc2_);
}

// Verify that freeing an empty assertion_description_array does not cause any
// errors. This also covers the case where an assertion_description_array is
// freed twice, because AssertionDescriptionTest::TearDown will free the
// array object used in this test.
TEST_F(AssertionDescriptionTest, FreeEmptyAssertionDescriptionsArray) {
  assertion_description_array_free(&array1_);
}

// Verify that adding assertion_descriptions to an array is working correctly.
TEST_F(AssertionDescriptionTest, EmptyArrayAssignAt) {
  AddAndVerifyIdentities(/*num_descriptions=*/kIdentitiesTestPoolSize,
                         &array1_);
}

// Verify that overwriting an element in an assertion_description_array is
// working correctly.
TEST_F(AssertionDescriptionTest, PopulatedArrayAssignAt) {
  AddAndVerifyIdentities(/*num_descriptions=*/1, &array1_);
  EXPECT_TRUE(assertion_description_array_assign_at(
      /*index=*/0,
      identity_types_.back(),
      authority_types_.back().data(),
      authority_types_.back().size(),
      &array1_));
  VerifyAssertionDescription(/*test_pool_index=*/kIdentitiesTestPoolSize-1,
                             array1_.descriptions[0]);
}

// Verify that assigning at an index in an assertion_description_array that is
// out of the array's bounds will fail.
TEST_F(AssertionDescriptionTest, ArrayAssignAtOutOfBounds) {
  EXPECT_FALSE(assertion_description_array_assign_at(
      /*index=*/1,
      identity_types_.front(),
      authority_types_.front().data(),
      authority_types_.front().size(),
      &array1_));
}

// Verify that copying an assertion_description_array to an empty array is
// working correctly.
TEST_F(AssertionDescriptionTest, CopyAssertionDescriptionsArrayEmptyDest) {
  AddAndVerifyIdentities(/*num_descriptions=*/kIdentitiesTestPoolSize,
                         &array1_);
  assertion_description_array_init(/*count=*/0, &array2_);

  assertion_description_array_copy(/*src=*/&array1_, /*dest=*/&array2_);
  CheckArrayEquality(/*expected=*/array1_, /*actual=*/array2_);
}

// Verify that copy an assertion_description_array to a smaller array is working
// as expected.
TEST_F(AssertionDescriptionTest, CopyAssertionDescriptionsArraySmallerDest) {
  AddAndVerifyIdentities(/*num_descriptions=*/kIdentitiesTestPoolSize,
                         &array1_);
  AddAndVerifyIdentities(/*num_descriptions=*/kIdentitiesTestPoolSize-1,
                         &array2_);

  assertion_description_array_copy(/*src=*/&array1_, /*dest=*/&array2_);
  CheckArrayEquality(/*expected=*/array1_, /*actual=*/array2_);
}

// Verify that copy an assertion_description_array to a larger array is working
// as expected.
TEST_F(AssertionDescriptionTest, CopyAssertionDescriptionsArrayLargerDest) {
  AddAndVerifyIdentities(/*num_descriptions=*/kIdentitiesTestPoolSize-1,
                         &array1_);
  AddAndVerifyIdentities(/*num_descriptions=*/kIdentitiesTestPoolSize,
                         &array2_);

  assertion_description_array_copy(/*src=*/&array1_, /*dest=*/&array2_);
  CheckArrayEquality(/*expected=*/array1_, /*actual=*/array2_);
}

}  // namespace
}  // namespace asylo
