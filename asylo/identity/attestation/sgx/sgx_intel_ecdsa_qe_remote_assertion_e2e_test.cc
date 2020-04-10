/*
 *
 * Copyright 2020 Asylo authors
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_path_setter.h"
#include "asylo/identity/attestation/sgx/sgx_remote_assertion_generator_test_enclave_wrapper.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority_configs.h"
#include "asylo/platform/core/enclave_manager.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_macros.h"

ABSL_FLAG(std::string, generator_test_enclave_path, "",
          "Path to the generator test enclave");

namespace asylo {
namespace {

using ::testing::Test;

// Tests generation and verification of Intel ECDSA Quoting Enclave assertions,
// including integration with the Intel DCAP software stack. The purpose of this
// test is end-to-end integration with the Intel stack and not full coverage of
// the Asylo assertion generator bits.
class SgxIntelEcdsaQeRemoteAssertionE2eTest : public Test {
 protected:
  static void SetUpTestSuite() {
    sgx::SetIntelEnclaveDirFromFlags();
    ASYLO_ASSERT_OK(EnclaveManager::Configure(EnclaveManagerOptions{}));
    ASYLO_ASSERT_OK_AND_ASSIGN(enclave_manager_, EnclaveManager::Instance());
    ASYLO_ASSERT_OK(LoadTestEnclave());
  }

  static void TearDownTestSuite() { delete test_enclave_; }

  void SetUp() override {
    EnclaveAssertionAuthorityConfig config;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        config,
        experimental::CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig());

    ASYLO_ASSERT_OK(test_enclave_->ResetGenerator());
    ASYLO_ASSERT_OK(test_enclave_->Initialize(config.config()));
  }

  static EnclaveManager *enclave_manager_;
  static SgxRemoteAssertionGeneratorTestEnclaveWrapper *test_enclave_;

 private:
  static Status LoadTestEnclave() {
    sgx::SgxRemoteAssertionGeneratorTestEnclaveConfig enclave_config;
    SetSgxIntelEcdsaQeRemoteAssertionDescription(
        enclave_config.mutable_description());

    std::unique_ptr<SgxRemoteAssertionGeneratorTestEnclaveWrapper> wrapper;
    ASYLO_ASSIGN_OR_RETURN(
        wrapper,
        SgxRemoteAssertionGeneratorTestEnclaveWrapper::Load(
            enclave_manager_, absl::GetFlag(FLAGS_generator_test_enclave_path),
            enclave_config));
    test_enclave_ = wrapper.release();

    return Status::OkStatus();
  }
};

EnclaveManager *SgxIntelEcdsaQeRemoteAssertionE2eTest::enclave_manager_;
SgxRemoteAssertionGeneratorTestEnclaveWrapper
    *SgxIntelEcdsaQeRemoteAssertionE2eTest::test_enclave_;

TEST_F(SgxIntelEcdsaQeRemoteAssertionE2eTest, VerifyAssertionGeneration) {
  constexpr char kUserData[] = "This is some user data";
  AssertionRequest request;
  SetSgxIntelEcdsaQeRemoteAssertionDescription(request.mutable_description());

  Assertion assertion;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion,
                             test_enclave_->Generate(kUserData, request));

  EXPECT_THAT(assertion.description(), EqualsProto(request.description()));

  EXPECT_GT(assertion.assertion().size(), 0);
}

}  // namespace
}  // namespace asylo
