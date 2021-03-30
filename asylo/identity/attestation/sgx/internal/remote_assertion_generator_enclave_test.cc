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
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "asylo/client.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key.pb.h"
#include "asylo/identity/attestation/sgx/internal/fake_pce.h"
#include "asylo/identity/attestation/sgx/internal/pce_util.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_constants.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave_util.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_test_util_enclave.pb.h"
#include "asylo/identity/attestation/sgx/internal/sgx_infrastructural_enclave_manager.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/sealing/sealed_secret.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
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
using ::testing::Ge;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::SizeIs;

constexpr char kRemoteAssertionGeneratorTestUtilEnclaveName[] =
    "remote assertion generator test util enclave";
constexpr char kTestName[] = "RemoteAssertionGeneratorEnclaveTest";
constexpr int kNumThreads = 5;
constexpr char kRsaPublicKey3072DerHex[] =
    "3082018a02820181009ec70e5aa931243768ca8d5b06d6f0a0d3eed0d8f51c6d32c990baeb"
    "7cbadd094fe499ba0559e05d0599a55b6521bc07979c9a838d2056568513d41409bec9f938"
    "7f3ca8f1d98a726eb1b7959a5cb88419eb92c4f14e0b234351911d8fb31c090da456ac36dd"
    "f2c42db8916909bd251dc9d061b551d4d9341dc4ffb0d5f030f1ed9e6dd8e019d6a63d2094"
    "8d4b3188cb6a860d5524467963ab163a978214b426556f0472cc799c6668133740202db131"
    "5a62b5908d95e22ed3d9989425e91802b0496d0d137dfe86006d1e6127c862c0f25ab3238e"
    "ba90db0507cfa214c272b78e05713506e6a1d5592336945ab1a24f1763d579f21f3e82a7af"
    "ed847b407aa4e0cda51cd57a4a09e0496b1b56da6ce8eb82283aae857fb8ddf34c6eef5ec0"
    "18ff269a3f562679bf60b90757a2722a5ba241e674ae5b4b5cbe251fc8c10b8d69fe977637"
    "ffce2fc2ed2673ac86b5bf47da72f47a55214b4161c915e3b15b11f2085471b818da18f04f"
    "9d31e60ff7ce1d681951894b6b20a30f6f43525d3749b90203010001";

void SetTestAsymmetricEncryptionKeyProto(
    AsymmetricEncryptionKeyProto *asymmetric_encryption_key_proto) {
  asymmetric_encryption_key_proto->set_encryption_scheme(
      AsymmetricEncryptionScheme::RSA3072_OAEP);
  asymmetric_encryption_key_proto->set_encoding(
      AsymmetricKeyEncoding::ASYMMETRIC_KEY_DER);
  asymmetric_encryption_key_proto->set_key_type(
      AsymmetricEncryptionKeyProto::ENCRYPTION_KEY);
  asymmetric_encryption_key_proto->set_key(
      absl::HexStringToBytes(kRsaPublicKey3072DerHex));
}

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
    ASYLO_ASSERT_OK_AND_ASSIGN(enclave_manager_, EnclaveManager::Instance());
  }

  void SetUp() override {
    ASSERT_FALSE(
        absl::GetFlag(FLAGS_remote_assertion_generator_test_util_enclave_path)
            .empty());
    ASSERT_FALSE(
        absl::GetFlag(FLAGS_remote_assertion_generator_enclave_path).empty());
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

  StatusOr<EnclaveLoadConfig> GetAgeEnclaveLoadConfig() {
    ASYLO_ASSIGN_OR_RETURN(server_address_, CreateUdsServerAddress());
    return SgxInfrastructuralEnclaveManager::GetAgeEnclaveLoadConfig(
        absl::GetFlag(FLAGS_remote_assertion_generator_enclave_path),
        /*is_debuggable_enclave=*/true, server_address_,
        GetSgxLocalAssertionAuthorityTestConfig());
  }

  Status InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress() {
    EnclaveLoadConfig load_config;
    ASYLO_ASSIGN_OR_RETURN(load_config, GetAgeEnclaveLoadConfig());
    return InitializeRemoteAssertionGeneratorEnclave(load_config);
  }

  Status InitializeRemoteAssertionGeneratorEnclave(
      const EnclaveLoadConfig &load_config) {
    ASYLO_RETURN_IF_ERROR(enclave_manager_->LoadEnclave(load_config));
    remote_assertion_generator_enclave_client_ =
        enclave_manager_->GetClient(load_config.name());
    return absl::OkStatus();
  }

  Status StartTestUtilEnclave() {
    // Create an EnclaveLoadConfig object.
    EnclaveLoadConfig load_config;
    load_config.set_name(kRemoteAssertionGeneratorTestUtilEnclaveName);
    *load_config.mutable_config()->add_enclave_assertion_authority_configs() =
        GetSgxLocalAssertionAuthorityTestConfig();

    // Create an SgxLoadConfig object.
    SgxLoadConfig sgx_config;
    SgxLoadConfig::FileEnclaveConfig file_enclave_config;
    file_enclave_config.set_enclave_path(
        absl::GetFlag(FLAGS_remote_assertion_generator_test_util_enclave_path));
    *sgx_config.mutable_file_enclave_config() = file_enclave_config;
    sgx_config.set_debug(true);

    // Set an SGX message extension to load_config.
    *load_config.MutableExtension(sgx_load_config) = sgx_config;

    ASYLO_RETURN_IF_ERROR(enclave_manager_->LoadEnclave(load_config));
    remote_assertion_generator_test_util_enclave_client_ =
        enclave_manager_->GetClient(
            kRemoteAssertionGeneratorTestUtilEnclaveName);
    return absl::OkStatus();
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
      return Status(absl::StatusCode::kInternal,
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
    EXPECT_THAT(assertion.verifying_key().signature_scheme(),
                Eq(SignatureScheme::ECDSA_P256_SHA256));
    if (assertion_has_certificate_chains) {
      EXPECT_THAT(assertion.certificate_chains(), SizeIs(1));
    } else {
      EXPECT_THAT(assertion.certificate_chains(), IsEmpty());
    }
  }

  StatusOr<SealedSecret> GetSealedSecretFromTestUtilEnclave() {
    if (!remote_assertion_generator_test_util_enclave_client_) {
      ASYLO_RETURN_IF_ERROR(StartTestUtilEnclave());
    }

    EnclaveInput test_util_enclave_input;
    *test_util_enclave_input
         .MutableExtension(remote_assertion_generator_test_util_enclave_input)
         ->mutable_get_sealed_secret_input()
         ->add_certificate_chains() = GetFakePckCertificateChain();

    EnclaveOutput test_util_enclave_output;
    ASYLO_RETURN_IF_ERROR(
        remote_assertion_generator_test_util_enclave_client_->EnterAndRun(
            test_util_enclave_input, &test_util_enclave_output));

    return std::move(
        *test_util_enclave_output
             .MutableExtension(
                 remote_assertion_generator_test_util_enclave_output)
             ->mutable_get_sealed_secret_output()
             ->mutable_sealed_secret());
  }

  StatusOr<TargetInfoProto> GetTargetInfoProtoFromClientEnclave() {
    if (!remote_assertion_generator_test_util_enclave_client_) {
      ASYLO_RETURN_IF_ERROR(StartTestUtilEnclave());
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
    return std::move(
        *client_enclave_output
             .MutableExtension(
                 remote_assertion_generator_test_util_enclave_output)
             ->mutable_get_target_info_output()
             ->mutable_target_info_proto());
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
             ->mutable_generate_key_and_csr_input()
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

  StatusOr<CertificateChain> CreateValidAgeCertificateChain() {
    std::unique_ptr<sgx::FakePce> fake_pce;
    ASYLO_ASSIGN_OR_RETURN(fake_pce, sgx::FakePce::CreateFromFakePki());

    SgxInfrastructuralEnclaveManager sgx_infra_enclave_manager(
        std::move(fake_pce), remote_assertion_generator_enclave_client_);

    CertificateChain certificate_chain;
    ASYLO_ASSIGN_OR_RETURN(*certificate_chain.add_certificates(),
                           sgx_infra_enclave_manager.CertifyAge());
    sgx::AppendFakePckCertificateChain(&certificate_chain);

    return certificate_chain;
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
    return std::move(
        *enclave_output
             .MutableExtension(
                 remote_assertion_generator_test_util_enclave_output)
             ->mutable_get_target_info_output()
             ->mutable_target_info_proto());
  }

  Status SetInputForGeneratePceInfoHardwareReport(EnclaveInput *enclave_input) {
    ASYLO_ASSIGN_OR_RETURN(
        *enclave_input
             ->MutableExtension(remote_assertion_generator_enclave_input)
             ->mutable_generate_pce_info_sgx_hardware_report_input()
             ->mutable_pce_target_info(),
        GetTargetInfoProtoFromTestUtilEnclave());

    AsymmetricEncryptionKeyProto *asymmetric_encryption_key_proto =
        enclave_input
            ->MutableExtension(remote_assertion_generator_enclave_input)
            ->mutable_generate_pce_info_sgx_hardware_report_input()
            ->mutable_ppid_encryption_key();
    SetTestAsymmetricEncryptionKeyProto(asymmetric_encryption_key_proto);
    return absl::OkStatus();
  }

  static EnclaveManager *enclave_manager_;

  EnclaveClient *remote_assertion_generator_test_util_enclave_client_;
  EnclaveClient *remote_assertion_generator_enclave_client_;

  std::string server_address_;
};

EnclaveManager *RemoteAssertionGeneratorEnclaveTest::enclave_manager_ = nullptr;

TEST_F(RemoteAssertionGeneratorEnclaveTest, InvalidConfigFails) {
  EnclaveLoadConfig load_config;
  ASYLO_ASSERT_OK_AND_ASSIGN(load_config, GetAgeEnclaveLoadConfig());

  // Missing AGE extension.
  load_config.mutable_config()->ClearExtension(
      remote_assertion_generator_enclave_config);

  EXPECT_THAT(InitializeRemoteAssertionGeneratorEnclave(load_config),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest, ConfigMissingServerAddressFails) {
  EnclaveLoadConfig load_config;
  ASYLO_ASSERT_OK_AND_ASSIGN(load_config, GetAgeEnclaveLoadConfig());

  // Missing server address.
  load_config.mutable_config()
      ->MutableExtension(remote_assertion_generator_enclave_config)
      ->clear_remote_assertion_generator_server_address();

  EXPECT_THAT(InitializeRemoteAssertionGeneratorEnclave(load_config),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest,
       StartServerWithoutKeyReturnsFailedPrecondition) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());

  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::NONE));

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  enclave_input
      .MutableExtension(remote_assertion_generator_test_util_enclave_input)
      ->mutable_get_remote_assertion_input()
      ->set_server_address(server_address_);
  EXPECT_THAT(remote_assertion_generator_test_util_enclave_client_->EnterAndRun(
                  enclave_input, &enclave_output),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest, StartServerWithSigningKeySuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());

  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::WITH_KEY));
  CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/false);
}

TEST_F(RemoteAssertionGeneratorEnclaveTest,
       StartServerWhenGrpcServerIsRunningFails) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());

  // Start SgxRemoteAssertionGenerator gRPC server.
  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::WITH_KEY));
  ASSERT_NO_FATAL_FAILURE(CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/false));

  // Try to start another SgxRemoteAssertionGenerator gRPC server while the
  // first is running.
  EXPECT_THAT(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::WITH_KEY),
      StatusIs(absl::StatusCode::kAlreadyExists,
               "Cannot start remote assertion generator gRPC server: server "
               "already exists"));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest, StartServerWithSecretSuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());

  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::WITH_SECRET));
  CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/true);
}

TEST_F(RemoteAssertionGeneratorEnclaveTest,
       StartServerWithSecretMultiThreadedSuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());

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
      if (status.code() == absl::StatusCode::kAlreadyExists) {
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
TEST_F(RemoteAssertionGeneratorEnclaveTest,
       TestGeneratePceInfoHardwareReportSuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  ASYLO_ASSERT_OK(SetInputForGeneratePceInfoHardwareReport(&enclave_input));
  ASYLO_ASSERT_OK(remote_assertion_generator_enclave_client_->EnterAndRun(
      enclave_input, &enclave_output));

  const ReportProto &report_proto =
      enclave_output.GetExtension(remote_assertion_generator_enclave_output)
          .generate_pce_info_sgx_hardware_report_output()
          .report();
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report,
                             ConvertReportProtoToHardwareReport(report_proto));

  Reportdata expected_reportdata;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      expected_reportdata,
      CreateReportdataForGetPceInfo(
          enclave_input.GetExtension(remote_assertion_generator_enclave_input)
              .generate_pce_info_sgx_hardware_report_input()
              .ppid_encryption_key()));
  EXPECT_THAT(report.body.reportdata.data, Eq(expected_reportdata.data));

  // Check that the test util enclave can verify the report produced by the
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
       TestGeneratePceInfoHardwareReportMissingTargetinfoFails) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  ASYLO_ASSERT_OK(SetInputForGeneratePceInfoHardwareReport(&enclave_input));

  enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
      ->mutable_generate_pce_info_sgx_hardware_report_input()
      ->clear_pce_target_info();
  EXPECT_THAT(remote_assertion_generator_enclave_client_->EnterAndRun(
                  enclave_input, &enclave_output),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "Input is missing pce_target_info"));
}

TEST_F(
    RemoteAssertionGeneratorEnclaveTest,
    TestGeneratePceInfoHardwareReportMissingSerializedPpidEncryptionKeyFails) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  ASYLO_ASSERT_OK(SetInputForGeneratePceInfoHardwareReport(&enclave_input));

  enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
      ->mutable_generate_pce_info_sgx_hardware_report_input()
      ->clear_ppid_encryption_key();
  EXPECT_THAT(remote_assertion_generator_enclave_client_->EnterAndRun(
                  enclave_input, &enclave_output),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "Input is missing ppid_encryption_key"));
}

// This test treats the util enclave as the PCE. We fetch the util enclave's
// Targetinfo instead of the Targetinfo for the PCE so we could call util
// enclave's VerifyReport entry point to verify that the report generated by
// RemoteAssertionGeneratorEnclave is a valid hardware report.
TEST_F(RemoteAssertionGeneratorEnclaveTest, GenerateKeyAndCsrSuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      *enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
           ->mutable_generate_key_and_csr_input()
           ->mutable_pce_target_info(),
      GetTargetInfoProtoFromTestUtilEnclave());
  ASYLO_ASSERT_OK(remote_assertion_generator_enclave_client_->EnterAndRun(
      enclave_input, &enclave_output));

  const std::string &serialized_pce_sign_report_payload =
      enclave_output.GetExtension(remote_assertion_generator_enclave_output)
          .generate_key_and_csr_output()
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
  const ReportProto &report_proto =
      enclave_output.GetExtension(remote_assertion_generator_enclave_output)
          .generate_key_and_csr_output()
          .report();
  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(report,
                             ConvertReportProtoToHardwareReport(report_proto));
  EXPECT_THAT(report.body.reportdata.data, Eq(expected_reportdata.data));

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
       UpdateCertsWithInvalidCertificateChainFails) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  UpdateCertsInput *update_certs_input =
      enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
          ->mutable_update_certs_input();
  update_certs_input->set_validate_certificate_chains(true);

  CertificateChain *certificate_chain =
      update_certs_input->add_certificate_chains();
  ASYLO_ASSERT_OK_AND_ASSIGN(*certificate_chain,
                             CreateValidAgeCertificateChain());

  // Case 1: Swap the PCK certificate and intermediate CA certificate to create
  // an invalid chain.
  ASSERT_THAT(certificate_chain->certificates().size(), Ge(3));
  certificate_chain->mutable_certificates()->SwapElements(1, 2);
  EXPECT_THAT(remote_assertion_generator_enclave_client_->EnterAndRun(
                  enclave_input, &enclave_output),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Cannot update certificates")));

  // Restore the certificate chain.
  certificate_chain->mutable_certificates()->SwapElements(1, 2);

  // Case 2: Remove the attestation key certificate to create a valid
  // certificate chain for wrong public key.
  certificate_chain->mutable_certificates()->erase(
      certificate_chain->certificates().cbegin());
  EXPECT_THAT(remote_assertion_generator_enclave_client_->EnterAndRun(
                  enclave_input, &enclave_output),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot update certificates")));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest,
       UpdateCertsForServerRunningWithoutKeySuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());
  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::NONE));

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      *enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
           ->mutable_update_certs_input()
           ->add_certificate_chains(),
      CreateValidAgeCertificateChain());

  ASYLO_ASSERT_OK(remote_assertion_generator_enclave_client_->EnterAndRun(
      enclave_input, &enclave_output));
  CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/true);
}

TEST_F(RemoteAssertionGeneratorEnclaveTest,
       UpdateCertsWithServerRunningSuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());
  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::WITH_KEY));
  ASSERT_NO_FATAL_FAILURE(CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/false));

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  UpdateCertsInput *update_certs_input =
      enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
          ->mutable_update_certs_input();
  ASYLO_ASSERT_OK_AND_ASSIGN(*update_certs_input->add_certificate_chains(),
                             CreateValidAgeCertificateChain());
  update_certs_input->set_validate_certificate_chains(false);

  ASYLO_ASSERT_OK(remote_assertion_generator_enclave_client_->EnterAndRun(
      enclave_input, &enclave_output));
  CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/true);
}

TEST_F(RemoteAssertionGeneratorEnclaveTest,
       UpdateCertsWithoutServerRunningSuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  UpdateCertsInput *update_certs_input =
      enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
          ->mutable_update_certs_input();
  ASYLO_ASSERT_OK_AND_ASSIGN(*update_certs_input->add_certificate_chains(),
                             CreateValidAgeCertificateChain());
  update_certs_input->set_validate_certificate_chains(false);
  update_certs_input->set_output_sealed_secret(true);

  ASYLO_ASSERT_OK(remote_assertion_generator_enclave_client_->EnterAndRun(
      enclave_input, &enclave_output));

  // Start server to verify that the UpdateCerts call is made when the gRPC
  // server is not running.
  ASYLO_ASSERT_OK(
      StartSgxRemoteAssertionGeneratorServer(StartServerOption::NONE));
  ASSERT_NO_FATAL_FAILURE(CheckServerRunningAndProducesValidRemoteAssertion(
      /*assertion_has_certificate_chains=*/true));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest, UpdateCertsNoAttestationKeyFails) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());
  ASYLO_ASSERT_OK(StartTestUtilEnclave());
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
      StatusIs(absl::StatusCode::kFailedPrecondition,
               "Cannot update certificates: no attestation key available"));
}

TEST_F(RemoteAssertionGeneratorEnclaveTest, GetEnclaveIdentitySuccess) {
  ASYLO_ASSERT_OK(
      InitializeRemoteAssertionGeneratorEnclaveWithRandomServerAddress());

  EnclaveInput enclave_input;
  EnclaveOutput enclave_output;
  *enclave_input.MutableExtension(remote_assertion_generator_enclave_input)
       ->mutable_get_enclave_identity_input() =
      GetEnclaveIdentityInput::default_instance();
  ASYLO_ASSERT_OK(remote_assertion_generator_enclave_client_->EnterAndRun(
      enclave_input, &enclave_output));

  const GetEnclaveIdentityOutput &output =
      enclave_output.GetExtension(remote_assertion_generator_enclave_output)
          .get_enclave_identity_output();
  EXPECT_TRUE(IsValidSgxIdentity(output.sgx_identity()));
}



}  // namespace
}  // namespace sgx
}  // namespace asylo
