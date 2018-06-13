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

#include "asylo/grpc/auth/util/bridge_cpp_to_c.h"

#include <cstdint>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/grpc/auth/null_credentials_options.h"
#include "asylo/identity/identity.pb.h"

namespace asylo {
namespace {

// Returns true if |expected| contains the same description as |actual|.
bool AssertionDescriptionIsEqual(const AssertionDescription &expected,
                                 const assertion_description &actual) {
  if (static_cast<int32_t>(expected.identity_type()) != actual.identity_type) {
    return false;
  }
  if (expected.authority_type().size() != actual.authority_type.size) {
    return false;
  }
  return memcmp(expected.authority_type().data(), actual.authority_type.data,
                actual.authority_type.size) == 0;
}

// Returns true if |expected| contains the same assertion_descriptions as
// |actual|.
bool AssertionDescriptionsAreEqual(
    const std::vector<AssertionDescription> &expected,
    const assertion_description_array &actual) {
  if (expected.size() != actual.count) {
    return false;
  }
  for (int i = 0; i < expected.size(); ++i) {
    if (!AssertionDescriptionIsEqual(expected[i], actual.descriptions[i])) {
      return false;
    }
  }
  return true;
}

// Returns true if the AAD in |expected| is the same as |actual|.
bool AdditionalAuthenticatedDataIsEqual(const std::string &expected,
                                        const safe_string &actual) {
  if (expected.size(), actual.size) {
    return false;
  }
  return strncmp(expected.c_str(), actual.data, actual.size) == 0;
}

// Returns true if |expected| contains the same credentials options as |actual|.
bool CredentialsOptionsAreEqual(
    const EnclaveCredentialsOptions &expected,
    const grpc_enclave_credentials_options &actual) {
  if (!AssertionDescriptionsAreEqual(expected.self_assertions,
                                     actual.self_assertions)) {
    return false;
  }
  if (!AssertionDescriptionsAreEqual(expected.accepted_peer_assertions,
                                     actual.accepted_peer_assertions)) {
    return false;
  }
  return AdditionalAuthenticatedDataIsEqual(
      expected.additional_authenticated_data,
      actual.additional_authenticated_data);
}

// This test fixture is used to handle the lifetime of a
// grpc_enclave_credentials_options structure for use in tests.
class BridgeCppToCTest : public ::testing::Test {
 protected:
  void SetUp() override {
    grpc_enclave_credentials_options_init(&bridge_options_);
  }

  void TearDown() override {
    grpc_enclave_credentials_options_destroy(&bridge_options_);
  }

  grpc_enclave_credentials_options bridge_options_;
};

// Verifies that CopyEnclaveCredentialsOptions correctly translates a non-empty
// EnclaveCredentialsOptions struct into a grpc_enclave_credentials_options.
TEST_F(BridgeCppToCTest, CopyEnclaveCredentialsOptionsNonEmpty) {
  EnclaveCredentialsOptions options = BidirectionalNullCredentialsOptions();
  CopyEnclaveCredentialsOptions(options, &bridge_options_);

  ASSERT_NO_FATAL_FAILURE(CredentialsOptionsAreEqual(options, bridge_options_));
}

// Verifies that CopyEnclaveCredentialsOptions correctly translates an empty
// EnclaveCredentialsOptions struct into a grpc_enclave_credentials_options.
TEST_F(BridgeCppToCTest, CopyEnclaveCredentialsOptionsEmpty) {
  EnclaveCredentialsOptions options;
  CopyEnclaveCredentialsOptions(options, &bridge_options_);

  ASSERT_NO_FATAL_FAILURE(CredentialsOptionsAreEqual(options, bridge_options_));
}

}  // namespace
}  // namespace asylo
