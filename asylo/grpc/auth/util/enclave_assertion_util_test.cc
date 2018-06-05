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

#include "asylo/grpc/auth/util/enclave_assertion_util.h"

#include <cstdint>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/identity/identity.pb.h"

namespace asylo {
namespace {

const int kIdentitiesTestPoolSize = 3;

const char kAuthorityType1[] = "Any";
const char kAuthorityType2[] = "SGX Local";
const char kAuthorityType3[] = "Google CA";

// This file tests the utility library provided for use with the
// AssertionDescription proto. Currently, there is only one function provided in
// this library: CopyAssertionDescriptions.

// A test fixture is used to store input and output parameters to the
// CopyAssertionDescriptions function. The test fixture also handles destruction
// of assertion_description_array objects that are created.
class AssertionUtilTest : public ::testing::Test {
 protected:
  void SetUp() override {
    std::vector<EnclaveIdentityType> identity_types = {
        EnclaveIdentityType::NULL_IDENTITY, EnclaveIdentityType::CODE_IDENTITY,
        EnclaveIdentityType::CERT_IDENTITY};

    std::vector<std::string> authority_types = {kAuthorityType1, kAuthorityType2,
                                           kAuthorityType3};

    for (int i = 0; i < kIdentitiesTestPoolSize; ++i) {
      AssertionDescription assertion_desc;
      assertion_desc.set_identity_type(identity_types[i]);
      assertion_desc.set_authority_type(authority_types[i]);

      assertion_descriptions_vector_.push_back(assertion_desc);
    }
  }

  void TearDown() override {
    assertion_description_array_free(&assertion_descriptions_array_);
  }

  // Checks that |expected| contains the same assertion_descriptions as
  // |actual|.
  void CheckAssertionDescriptionsAreEqual(
      const std::vector<AssertionDescription> &expected,
      const assertion_description_array &actual) {
    ASSERT_EQ(expected.size(), actual.count);
    for (int i = 0; i < expected.size(); ++i) {
      const AssertionDescription &expected_assertion_desc = expected[i];
      const assertion_description &actual_assertion_desc =
          actual.descriptions[i];

      EXPECT_EQ(static_cast<int32_t>(expected_assertion_desc.identity_type()),
                actual_assertion_desc.identity_type);
      EXPECT_EQ(expected_assertion_desc.authority_type().size(),
                actual_assertion_desc.authority_type.size);
      EXPECT_EQ(0, memcmp(expected_assertion_desc.authority_type().data(),
                          actual_assertion_desc.authority_type.data,
                          actual_assertion_desc.authority_type.size));
    }
  }

  std::vector<AssertionDescription> assertion_descriptions_vector_;
  assertion_description_array assertion_descriptions_array_;
};

// Verifies that CopyAssertionDescriptions correctly translates a vector of
// AssertionDescriptions to an assertion_description_array.
TEST_F(AssertionUtilTest, CopyAssertionDescriptionsNonEmpty) {
  CopyAssertionDescriptions(assertion_descriptions_vector_,
                            &assertion_descriptions_array_);
  CheckAssertionDescriptionsAreEqual(assertion_descriptions_vector_,
                                     assertion_descriptions_array_);
}

// Verifies that copying an empty vector of AssertionDescriptions creates an
// empty assertion_description_array.
TEST_F(AssertionUtilTest, CopyAssertionDescriptionsEmpty) {
  assertion_descriptions_vector_.clear();
  CopyAssertionDescriptions(assertion_descriptions_vector_,
                            &assertion_descriptions_array_);
  CheckAssertionDescriptionsAreEqual(assertion_descriptions_vector_,
                                     assertion_descriptions_array_);
}

}  // namespace
}  // namespace asylo
