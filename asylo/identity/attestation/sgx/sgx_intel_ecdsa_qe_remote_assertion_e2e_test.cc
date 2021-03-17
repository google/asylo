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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <vector>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_path_setter.h"
#include "asylo/identity/attestation/sgx/internal/intel_certs/qe_identity.h"
#include "asylo/identity/attestation/sgx/sgx_intel_ecdsa_qe_remote_assertion_verifier.h"
#include "asylo/identity/attestation/sgx/sgx_remote_assertion_generator_test_enclave_wrapper.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/enclave_assertion_authority_configs.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/platform/core/enclave_manager.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/util/status_macros.h"

ABSL_FLAG(std::string, generator_test_enclave_path, "",
          "Path to the generator test enclave");

ABSL_FLAG(std::string, pck_cert_chain_path, "",
          "Path to the PEM-encoded PCK certificate chain for this platform");

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
    std::string path = absl::GetFlag(FLAGS_pck_cert_chain_path);
    if (path.empty()) {
      ASYLO_ASSERT_OK_AND_ASSIGN(
          assertion_authority_config_,
          experimental::CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig());
    } else {
      int fd = open(path.c_str(), O_RDONLY);
      ASSERT_NE(fd, -1) << strerror(errno);

      google::protobuf::io::FileInputStream input(fd);
      input.SetCloseOnDelete(true);

      CertificateChain cert_chain;
      ASSERT_TRUE(google::protobuf::TextFormat::Parse(&input, &cert_chain));

      ASYLO_ASSERT_OK_AND_ASSIGN(
          assertion_authority_config_,
          experimental::CreateSgxIntelEcdsaQeRemoteAssertionAuthorityConfig(
              cert_chain,
              ParseTextProtoOrDie(sgx::kIntelEcdsaQeIdentityTextproto)));
    }

    ASYLO_ASSERT_OK(test_enclave_->ResetGenerator());
    ASYLO_ASSERT_OK(
        test_enclave_->Initialize(assertion_authority_config_.config()));
  }

  static EnclaveManager *enclave_manager_;
  static SgxRemoteAssertionGeneratorTestEnclaveWrapper *test_enclave_;
  EnclaveAssertionAuthorityConfig assertion_authority_config_;

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

    return absl::OkStatus();
  }
};

EnclaveManager *SgxIntelEcdsaQeRemoteAssertionE2eTest::enclave_manager_;
SgxRemoteAssertionGeneratorTestEnclaveWrapper
    *SgxIntelEcdsaQeRemoteAssertionE2eTest::test_enclave_;

TEST_F(SgxIntelEcdsaQeRemoteAssertionE2eTest, VerifyAssertionOffer) {
  AssertionOffer offer;
  ASYLO_ASSERT_OK_AND_ASSIGN(offer, test_enclave_->CreateAssertionOffer());

  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(assertion_authority_config_.config()));
  EXPECT_THAT(verifier.CanVerify(offer), IsOkAndHolds(true));
}

TEST_F(SgxIntelEcdsaQeRemoteAssertionE2eTest, VerifyAssertionGeneration) {
  constexpr char kUserData[] = "This is some user data";
  AssertionRequest request;
  SetSgxIntelEcdsaQeRemoteAssertionDescription(request.mutable_description());

  Assertion assertion;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion,
                             test_enclave_->Generate(kUserData, request));

  EXPECT_THAT(assertion.description(), EqualsProto(request.description()));
  EXPECT_GT(assertion.assertion().size(), 0);

  SgxIntelEcdsaQeRemoteAssertionVerifier verifier;
  ASYLO_ASSERT_OK(verifier.Initialize(assertion_authority_config_.config()));

  if (absl::GetFlag(FLAGS_pck_cert_chain_path).empty()) {
    LOG(INFO) << "The flag " << FLAGS_pck_cert_chain_path.Name()
              << " was not set, so the test is skipping quote verification.";
  } else {
    LOG(INFO) << "Verifying quote with cert chain from "
              << absl::GetFlag(FLAGS_pck_cert_chain_path);
    EnclaveIdentity peer_identity;
    ASYLO_ASSERT_OK(verifier.Verify(kUserData, assertion, &peer_identity));
  }
}

}  // namespace
}  // namespace asylo
