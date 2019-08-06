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

#include <atomic>
#include <cstdlib>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "asylo/client.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/identity/sealed_secret.pb.h"
#include "asylo/identity/sgx/attestation_key.pb.h"
#include "asylo/identity/sgx/platform_provisioning.h"
#include "asylo/identity/sgx/platform_provisioning.pb.h"
#include "asylo/identity/sgx/remote_assertion.pb.h"
#include "asylo/identity/sgx/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/sgx/remote_assertion_generator_enclave_util.h"
#include "asylo/identity/sgx/remote_assertion_generator_test_util_enclave.pb.h"
#include "asylo/test/util/enclave_assertion_authority_configs.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/thread.h"

ABSL_FLAG(std::string, remote_assertion_generator_test_util_enclave_path, "",
          "Path to remote assertion generator test util enclave");
ABSL_FLAG(std::string, remote_assertion_generator_enclave_path, "",
          "Path to remote assertion generator enclave");

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::SizeIs;

constexpr char kRemoteAssertionGeneratorTestUtilEnclaveName[] =
    "remote assertion generator test util enclave";
constexpr char kAssertionGeneratorEnclaveName[] =
    "remote assertion generator enclave";
constexpr char kCertificate[] = "Certificate";
constexpr char kTestName[] = "RemoteAssertionGeneratorEnclaveTest";
constexpr int kNumThreads = 5;

enum class StartServerOption { NONE, WITH_KEY, WITH_SECRET };

// This test expects the enclave paths to be passed in through the
// --remote_assertion_generator_test_util_enclave_path and
// --remote_assertion_generator_enclave_path flags.
class RemoteAssertionGeneratorEnclaveTest : public ::testing::Test {
 protected:
  RemoteAssertionGeneratorEnclaveTest()
      : remote_assertion_generator_test_util_enclave_client_(nullptr),
        remote_assertion_generator_enclave_client_(nullptr) {}

  static void SetUpTestSuite() {
    ASYLO_ASSERT_OK(EnclaveManager::Configure(EnclaveManagerOptions()));
    ASYLO_ASSERT_OK_AND_ASSIGN(enclave_manager_, EnclaveManager::Instance());
  }

  void SetUp() override {
    ASSERT_FALSE(
        absl::GetFlag(FLAGS_remote_assertion_generator_test_util_enclave_path)
            .empty());
    ASSERT_FALSE(
        absl::GetFlag(FLAGS_remote_assertion_generator_enclave_path).empty());

    // Both enclaves must have the same local attestation domain in
    // order for SGX local attestation to work.
    *remote_assertion_generator_enclave_config_
         .add_enclave_assertion_authority_configs() =
        GetSgxLocalAssertionAuthorityTestConfig();
    remote_assertion_generator_test_util_enclave_config_ =
        remote_assertion_generator_enclave_config_;
  }

  void TearDown() override {
    EnclaveFinal enclave_final;
    if (remote_assertion_generator_test_util_enclave_client_) {
      ASYLO_EXPECT_OK(enclave_manager_->DestroyEnclave(
          remote_assertion_generator_test_util_enclave_client_, enclave_final,
          /*skip_finalize=*/false));
    }
    if (remote_assertion_generator_enclave_client_) {
      ASYLO_EXPECT_OK(enclave_manager_->DestroyEnclave(
          remote_assertion_generator_enclave_client_, enclave_final,
          /*skip_finalize=*/false));
    }
  }

  Status InitializeRemoteAssertionGeneratorEnclave(
      const EnclaveConfig &config) {
    SgxLoader loader(
        absl::GetFlag(FLAGS_remote_assertion_generator_enclave_path),
        /*debug=*/true);
    ASYLO_RETURN_IF_ERROR(enclave_manager_->LoadEnclave(
        kAssertionGeneratorEnclaveName, loader, config));
    remote_assertion_generator_enclave_client_ =
        enclave_manager_->GetClient(kAssertionGeneratorEnclaveName);
    return Status::OkStatus();
  }

  Status InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress() {
    ASYLO_ASSIGN_OR_RETURN(server_address_, CreateUdsServerAddress());
    remote_assertion_generator_enclave_config_
        .MutableExtension(remote_assertion_generator_enclave_config)
        ->set_remote_assertion_generator_server_address(server_address_);
    return InitializeRemoteAssertionGeneratorEnclave(
        remote_assertion_generator_enclave_config_);
  }

  Status StartTestUtilEnclave(const EnclaveConfig &config) {
    SgxLoader loader(
        absl::GetFlag(FLAGS_remote_assertion_generator_test_util_enclave_path),
        /*debug=*/true);
    ASYLO_RETURN_IF_ERROR(enclave_manager_->LoadEnclave(
        kRemoteAssertionGeneratorTestUtilEnclaveName, loader, config));
    remote_assertion_generator_test_util_enclave_client_ =
        enclave_manager_->GetClient(
            kRemoteAssertionGeneratorTestUtilEnclaveName);
    return Status::OkStatus();
  }

  // Creates an unix domain socket server address at a randomly generated
  // directory and returns the socket address.
  StatusOr<std::string> CreateUdsServerAddress() {
    // mkdtemp requires that the last 6 characters of the input pattern
    // are Xs, and the string is modified by replacing those characters.
    std::string tmp_path = absl::StrCat("/tmp/", kTestName, "_XXXXXX");
    std::vector<char> buffer(tmp_path.size() + 1, '\0');
    std::copy(tmp_path.begin(), tmp_path.end(), buffer.begin());
    if (mkdtemp(buffer.data()) == nullptr) {
      return Status(error::GoogleError::INTERNAL,
                    "Failed to create random test directory");
    }
    std::string random_server_address =
        absl::StrCat("unix:", buffer.data(), ".sock");
    return random_server_address;
  }

  void CheckServerRunningAndProducesValidRemoteAssertion(
      bool assertion_has_certificate_chains) {
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    enclave_input
        .MutableExtension(remote_assertion_generator_test_util_enclave_input)
        ->mutable_get_remote_assertion_input()
        ->set_server_address(server_address_);
    ASYLO_ASSERT_OK(
        remote_assertion_generator_test_util_enclave_client_->EnterAndRun(
            enclave_input, &enclave_output));
    RemoteAssertion assertion =
        enclave_output
            .GetExtension(remote_assertion_generator_test_util_enclave_output)
            .get_remote_assertion_output()
            .assertion();
    EXPECT_TRUE(assertion.has_signature());
    EXPECT_THAT(assertion.signature_scheme(),
                Eq(SignatureScheme::ECDSA_P256_SHA256));
    if (assertion_has_certificate_chains) {
      EXPECT_THAT(assertion.certificate_chains(), SizeIs(1));
      EXPECT_THAT(assertion.certificate_chains().at(0).certificates(),
                  SizeIs(1));
      const Certificate &certificate =
          assertion.certificate_chains().at(0).certificates(0);
      EXPECT_THAT(certificate.format(), Eq(Certificate::X509_DER));
      EXPECT_EQ(certificate.data(), kCertificate);
    } else {
      EXPECT_THAT(assertion.certificate_chains(), IsEmpty());
    }
  }

  StatusOr<SealedSecret> GetSealedSecretFromTestUtilEnclave() {
    if (!remote_assertion_generator_test_util_enclave_client_) {
      ASYLO_RETURN_IF_ERROR(StartTestUtilEnclave(
          remote_assertion_generator_test_util_enclave_config_));
    }

    EnclaveInput test_util_enclave_input;
    Certificate *certificate =
        test_util_enclave_input
            .MutableExtension(
                remote_assertion_generator_test_util_enclave_input)
            ->mutable_get_sealed_secret_input()
            ->add_certificate_chains()
            ->add_certificates();
    certificate->set_format(Certificate::X509_DER);
    certificate->set_data(kCertificate);

    EnclaveOutput test_util_enclave_output;
    ASYLO_RETURN_IF_ERROR(
        remote_assertion_generator_test_util_enclave_client_->EnterAndRun(
            test_util_enclave_input, &test_util_enclave_output));

    return test_util_enclave_output
        .MutableExtension(remote_assertion_generator_test_util_enclave_output)
        ->get_sealed_secret_output()
        .sealed_secret();
  }

  StatusOr<TargetInfoProto> GetTargetInfoProtoFromClientEnclave() {
    if (!remote_assertion_generator_test_util_enclave_client_) {
      ASYLO_RETURN_IF_ERROR(StartTestUtilEnclave(
          remote_assertion_generator_test_util_enclave_config_));
    }
    EnclaveInput client_enclave_input;
    EnclaveOutput client_enclave_output;

    *client_enclave_input
         .MutableExtension(remote_assertion_generator_test_util_enclave_input)
         ->mutable_get_target_info_input() =
        GetTargetInfoInput::default_instance();
    ASYLO_RETURN_IF_ERROR(
        remote_assertion_generator_test_util_enclave_client_->EnterAndRun(
            client_enclave_input, &client_enclave_output));
    return client_enclave_output
        .MutableExtension(remote_assertion_generator_test_util_enclave_output)
        ->get_target_info_output()
        .target_info_proto();
  }

  // Generates an attestation key inside remote assertion generator enclave.
  // The output is not used since the method is only used for setting up test
  // environment.
  Status GenerateAttestationKeyForRemoteAssertionGeneratorEnclave() {
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    ASYLO_ASSIGN_OR_RETURN(
        *enclave_input
             .MutableExtension(remote_assertion_generator_enclave_input)
             ->mutable_generate_key_and_csr_request_input()
             ->mutable_pce_target_info(),
        GetTargetInfoProtoFromTestUtilEnclave());
    return remote_assertion_generator_enclave_client_->EnterAndRun(
        enclave_input, &enclave_output);
  }

  Status StartSgxRemoteAssertionGeneratorServer(StartServerOption option) {
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    StartServerRequestInput *start_server_request_input =
        enclave_input
            .MutableExtension(remote_assertion_generator_enclave_input)
            ->mutable_start_server_request_input();
    switch (option) {
      case StartServerOption::NONE:
        break;
      case StartServerOption::WITH_KEY: {
        ASYLO_RETURN_IF_ERROR(
            GenerateAttestationKeyForRemoteAssertionGeneratorEnclave());
        break;
      }
      case StartServerOption::WITH_SECRET: {
        ASYLO_ASSIGN_OR_RETURN(
            *start_server_request_input->mutable_sealed_secret(),
            GetSealedSecretFromTestUtilEnclave());
        break;
      }
    }
    return remote_assertion_generator_enclave_client_->EnterAndRun(
        enclave_input, &enclave_output);
  }

  StatusOr<TargetInfoProto> GetTargetInfoProtoFromTestUtilEnclave() {
    EnclaveInput enclave_input;
    EnclaveOutput enclave_output;
    *enclave_input
         .MutableExtension(remote_assertion_generator_test_util_enclave_input)
         ->mutable_get_target_info_input() =
        GetTargetInfoInput::default_instance();
    ASYLO_RETURN_IF_ERROR(
        remote_assertion_generator_test_util_enclave_client_->EnterAndRun(
            enclave_input, &enclave_output));
    return enclave_output
        .MutableExtension(remote_assertion_generator_test_util_enclave_output)
        ->get_target_info_output()
        .target_info_proto();
  }

  // The config used to initialize the RemoteAssertionGenerator enclave.
  EnclaveConfig remote_assertion_generator_enclave_config_;

  // The config used to initialize the test util enclave.
  EnclaveConfig remote_assertion_generator_test_util_enclave_config_;

  static EnclaveManager *enclave_manager_;

  EnclaveClient *remote_assertion_generator_test_util_enclave_client_;
  EnclaveClient *remote_assertion_generator_enclave_client_;

  std::string server_address_;
};

EnclaveManager *RemoteAssertionGeneratorEnclaveTest::enclave_manager_ = nullptr;

TEST_F(RemoteAssertionGeneratorEnclaveTest, InvalidConfigFails) {
  remote_assertion_generator_enclave_config_.ClearExtension(
      remote_assertion_generator_enclave_config);
  EXPECT_THAT(InitializeRemoteAssertionGeneratorEnclave(
                  remote_assertion_generator_enclave_config_),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest, ConfigMissingServerAddressFails) {
  remote_assertion_generator_enclave_config_
      .MutableExtension(remote_assertion_generator_enclave_config)
      ->clear_remote_assertion_generator_server_address();
  EXPECT_THAT(InitializeRemoteAssertionGeneratorEnclave(
                  remote_assertion_generator_enclave_config_),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest,
       StartServerWithoutSealedSecretOrSigningKeyFails) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());

  EXPECT_THAT(StartSgxRemoteAssertionGeneratorServer(StartServerOption::NONE),
              StatusIs(error::GoogleError::FAILED_PRECONDITION,
                       "Cannot start remote assertion generator gRPC server: "
                       "no attestation key available"));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest, StartServerWithSigningKeySuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave(
      remote_assertion_generator_test_util_enclave_config_));

  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::WITH_KEY));
  CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/false);
}

TEST_F(RemoteAssertionGeneratorEnclaveTest,
       StartServerWhenGrpcServerIsRunningFails) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave(
      remote_assertion_generator_test_util_enclave_config_));

  // Start SgxRemoteAssertionGenerator gRPC server.
  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::WITH_KEY));
  ASSERT_NO_FATAL_FAILURE(CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/false));

  // Try to start another SgxRemoteAssertionGenerator gRPC server while the
  // first is running.
  EXPECT_THAT(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::WITH_KEY),
      StatusIs(error::GoogleError::ALREADY_EXISTS,
               "Cannot start remote assertion generator gRPC server: server "
               "already exists"));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest, StartServerWithSecretSuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave(
      remote_assertion_generator_test_util_enclave_config_));

  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::WITH_SECRET));
  CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/true);
}

TEST_F(RemoteAssertionGeneratorEnclaveTest,
       StartServerWithSecretMultiThreadedSuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave(
      remote_assertion_generator_test_util_enclave_config_));

  std::vector<EnclaveInput> enclave_inputs;
  std::vector<EnclaveOutput> enclave_outputs;
  enclave_inputs.reserve(kNumThreads);
  enclave_outputs.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    enclave_inputs.emplace_back(EnclaveInput::default_instance());
    ASYLO_ASSERT_OK_AND_ASSIGN(
        *enclave_inputs[i]
             .MutableExtension(remote_assertion_generator_enclave_input)
             ->mutable_start_server_request_input()
             ->mutable_sealed_secret(),
        GetSealedSecretFromTestUtilEnclave());
    enclave_outputs.emplace_back(EnclaveOutput::default_instance());
  }

  std::vector<Thread> threads;
  threads.reserve(kNumThreads);
  std::atomic<int> failure_count(0);
  std::atomic<int> success_count(0);
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([&enclave_inputs, &enclave_outputs, &failure_count,
                          &success_count, this, i] {
      Status status = remote_assertion_generator_enclave_client_->EnterAndRun(
          enclave_inputs[i], &enclave_outputs[i]);

      if (status.ok()) {
        success_count++;
      }
      if (status.Is(error::GoogleError::ALREADY_EXISTS)) {
        failure_count++;
      }
    });
  }

  for (Thread &thread : threads) {
    thread.Join();
  }
  // Verify the SgxRemoteAssertionGenerator gRPC server only started once and
  // all other starting server attempts received a server already exists error.
  ASSERT_THAT(success_count, Eq(1));
  ASSERT_THAT(failure_count, Eq(kNumThreads - 1));

  CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/true);
}

// This test treats the util enclave as the PCE. We fetch the util enclave's
// Targetinfo instead of the Targetinfo for the PCE so we could call util
// enclave's VerifyReport entry point to verify that the report generated by
// RemoteAssertionGeneratorEnclave is a valid hardware report.
TEST_F(RemoteAssertionGeneratorEnclaveTest, GenerateKeyAndCsrSuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave(
      remote_assertion_generator_test_util_enclave_config_));

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      *enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
           ->mutable_generate_key_and_csr_request_input()
           ->mutable_pce_target_info(),
      GetTargetInfoProtoFromTestUtilEnclave());
  ASYLO_ASSERT_OK(remote_assertion_generator_enclave_client_->EnterAndRun(
      enclave_input, &enclave_output));

  std::string serialized_pce_sign_report_payload =
      enclave_output
          .MutableExtension(remote_assertion_generator_enclave_output)
          ->generate_key_and_csr_request_output()
          .pce_sign_report_payload();

  PceSignReportPayload pce_sign_report_payload;
  ASSERT_TRUE(pce_sign_report_payload.ParseFromString(
      serialized_pce_sign_report_payload));
  EXPECT_THAT(pce_sign_report_payload.version(),
              Eq(kPceSignReportPayloadVersion));

  const AttestationPublicKey &public_key =
      pce_sign_report_payload.attestation_public_key();
  EXPECT_THAT(public_key.version(), Eq(kAttestationPublicKeyVersion));
  EXPECT_THAT(public_key.purpose(), Eq(kAttestationPublicKeyPurpose));

  AsymmetricSigningKeyProto asymmetric_signing_key_proto =
      public_key.attestation_public_key();
  EXPECT_THAT(asymmetric_signing_key_proto.key_type(),
              Eq(AsymmetricSigningKeyProto::VERIFYING_KEY));
  EXPECT_THAT(asymmetric_signing_key_proto.signature_scheme(),
              Eq(SignatureScheme::ECDSA_P256_SHA256));
  EXPECT_THAT(asymmetric_signing_key_proto.encoding(),
              Eq(AsymmetricKeyEncoding::ASYMMETRIC_KEY_DER));
  EXPECT_THAT(EcdsaP256Sha256VerifyingKey::CreateFromDer(
                  asymmetric_signing_key_proto.key()),
              IsOk());

  // Check that the Reportdata in Report is for PceSignReport protocol.
  Reportdata expected_reportdata;
  ASYLO_ASSERT_OK_AND_ASSIGN(expected_reportdata,
                             GenerateReportdataForPceSignReportProtocol(
                                 serialized_pce_sign_report_payload));
  ReportProto report_proto =
      enclave_output
          .MutableExtension(remote_assertion_generator_enclave_output)
          ->generate_key_and_csr_request_output()
          .report();
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report,
                             ConvertReportProtoToHardwareReport(report_proto));
  EXPECT_THAT(report.reportdata.data, Eq(expected_reportdata.data));

  // Check that the test util enclave can verify the report produced by the AGE.
  EnclaveInput client_enclave_input;
  EnclaveOutput client_enclave_output;
  *client_enclave_input
       .MutableExtension(remote_assertion_generator_test_util_enclave_input)
       ->mutable_verify_report_input()
       ->mutable_report_proto() = report_proto;
  ASYLO_ASSERT_OK(
      remote_assertion_generator_test_util_enclave_client_->EnterAndRun(
          client_enclave_input, &client_enclave_output));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest,
       GenerateKeyAndCsrMissingTargetInfoProtoFails) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  *enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
       ->mutable_generate_key_and_csr_request_input() =
      GenerateKeyAndCsrRequestInput::default_instance();
  EXPECT_THAT(remote_assertion_generator_enclave_client_->EnterAndRun(
                  enclave_input, &enclave_output),
              StatusIs(error::GoogleError::INVALID_ARGUMENT,
                       "Input is missing pce_target_info"));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest, UpdateCertsNoServerFails) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave(
      remote_assertion_generator_test_util_enclave_config_));
  ASYLO_ASSERT_OK(GenerateAttestationKeyForRemoteAssertionGeneratorEnclave());

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  *enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
       ->mutable_update_certs_input() = UpdateCertsInput::default_instance();
  EXPECT_THAT(remote_assertion_generator_enclave_client_->EnterAndRun(
                  enclave_input, &enclave_output),
              StatusIs(error::GoogleError::FAILED_PRECONDITION,
                       "Cannot update certificates: remote assertion generator "
                       "server does not exist"));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest, UpdateCertsNoAttestationKeyFails) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave(
      remote_assertion_generator_test_util_enclave_config_));
  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::WITH_KEY));
  ASSERT_NO_FATAL_FAILURE(CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/false));

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  *enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
       ->mutable_update_certs_input() = UpdateCertsInput::default_instance();
  EXPECT_THAT(
      remote_assertion_generator_enclave_client_->EnterAndRun(enclave_input,
                                                              &enclave_output),
      StatusIs(error::GoogleError::FAILED_PRECONDITION,
               "Cannot update certificates: no attestation key available"));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest, UpdateCertsSuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave(
      remote_assertion_generator_test_util_enclave_config_));
  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::WITH_KEY));
  ASSERT_NO_FATAL_FAILURE(CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/false));

  ASYLO_ASSERT_OK(GenerateAttestationKeyForRemoteAssertionGeneratorEnclave());
  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  Certificate *certificate =
      enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
          ->mutable_update_certs_input()
          ->add_certificate_chains()
          ->add_certificates();
  certificate->set_format(Certificate::X509_DER);
  certificate->set_data(kCertificate);
  ASYLO_ASSERT_OK(remote_assertion_generator_enclave_client_->EnterAndRun(
      enclave_input, &enclave_output));
  CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/true);
}



}  // namespace
}  // namespace sgx
}  // namespace asylo
