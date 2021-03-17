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

#include <memory>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/time/time.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/enclave.pb.h"
#include "asylo/enclave_manager.h"
#include "asylo/grpc/auth/enclave_channel_credentials.h"
#include "asylo/grpc/auth/null_credentials_options.h"
#include "asylo/grpc/auth/peer_sgx_age_remote_credentials_options.h"
#include "asylo/grpc/util/enclave_server.pb.h"
#include "asylo/identity/attestation/sgx/internal/fake_pce.h"
#include "asylo/identity/attestation/sgx/internal/sgx_infrastructural_enclave_manager.h"
#include "asylo/identity/init.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/test/grpc/client_enclave.pb.h"
#include "asylo/test/grpc/client_side_auth_test_constants.h"
#include "asylo/test/grpc/messenger_client_impl.h"
#include "asylo/test/grpc/messenger_server_impl.h"
#include "asylo/test/util/enclave_assertion_authority_configs.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/enclave_test_launcher.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

ABSL_FLAG(std::string, age_path, "", "Path to the assertion generator enclave");
ABSL_FLAG(std::string, client_enclave_path, "", "Path to the client enclave");

namespace asylo {
namespace {

constexpr char kAddress[] = "[::1]";
constexpr char kClientEnclaveName[] = "Client enclave";

class SgxAgeRemoteServerEnclaveTest : public EnclaveTest {
 protected:
  void SetUp() override {
    ASYLO_ASSERT_OK_AND_ASSIGN(enclave_manager_, EnclaveManager::Instance());

    std::string age_server_address;
    ASYLO_ASSERT_OK_AND_ASSIGN(age_server_address, SetUpAge());
    SgxIdentity age_identity;
    ASYLO_ASSERT_OK_AND_ASSIGN(age_identity,
                               sgx_infra_enclave_manager_->AgeGetSgxIdentity());

    *config_.add_enclave_assertion_authority_configs() =
        GetNullAssertionAuthorityTestConfig();
    *config_.add_enclave_assertion_authority_configs() =
        GetSgxLocalAssertionAuthorityTestConfig();

    sgx_age_remote_config_ = GetSgxAgeRemoteAssertionAuthorityTestConfig(
        age_server_address, age_identity);
    *config_.add_enclave_assertion_authority_configs() = sgx_age_remote_config_;

    ASYLO_ASSERT_OK(SetUpServer());
    ASYLO_ASSERT_OK(SetUpClient());
  }

  void TearDown() override {
    EnclaveFinal final;
    ASYLO_ASSERT_OK(client_launcher_.TearDown(final));
    ASYLO_ASSERT_OK(enclave_manager_->DestroyEnclave(age_client_, final));
    ASSERT_NO_FATAL_FAILURE(EnclaveTest::TearDown());
  }

  StatusOr<std::string> SetUpAge() {
    // Establish a random UDS address for the AGE.
    char path[] = "/tmp/SgxAgeRemoteServerEnclaveTest.XXXXXX";
    if (mkdtemp(path) == nullptr) {
      return absl::InternalError(absl::StrCat(
          "Failed to create random test directory: ", strerror(errno)));
    }
    std::string age_server_address = absl::StrCat("unix:", path, ".sock");
    EnclaveLoadConfig load_config =
        SgxInfrastructuralEnclaveManager::GetAgeEnclaveLoadConfig(
            absl::GetFlag(FLAGS_age_path),
            /*is_debuggable_enclave=*/true, age_server_address,
            GetSgxLocalAssertionAuthorityTestConfig());

    ASYLO_RETURN_IF_ERROR(enclave_manager_->LoadEnclave(load_config));
    age_client_ = enclave_manager_->GetClient(load_config.name());

    // Set-up a Fake PCE
    std::unique_ptr<sgx::FakePce> fake_pce;
    ASYLO_ASSIGN_OR_RETURN(fake_pce, sgx::FakePce::CreateFromFakePki());

    sgx_infra_enclave_manager_ =
        absl::make_unique<SgxInfrastructuralEnclaveManager>(std::move(fake_pce),
                                                            age_client_);

    // Certify the AGE with the Fake SGX PKI.
    CertificateChain certificate_chain;
    ASYLO_ASSIGN_OR_RETURN(*certificate_chain.add_certificates(),
                           sgx_infra_enclave_manager_->CertifyAge());
    sgx::AppendFakePckCertificateChain(&certificate_chain);

    // Call AGE::UpdateCerts().
    ASYLO_RETURN_IF_ERROR(sgx_infra_enclave_manager_->AgeUpdateCerts(
        {certificate_chain},
        /*validate_cert_chains=*/false));

    // Call AGE::StartServer().
    ASYLO_RETURN_IF_ERROR(sgx_infra_enclave_manager_->AgeStartServer());

    return age_server_address;
  }

  Status SetUpServer() {
    ServerConfig *config = config_.MutableExtension(server_input_config);
    config->set_host(kAddress);
    // Use a port of 0 for port auto-selection.
    config->set_port(0);
    SetUpBase();

    EnclaveInput input;
    EnclaveOutput output;
    ASYLO_RETURN_IF_ERROR(test_launcher_.Run(input, &output));
    ServerConfig server_config = output.GetExtension(server_output_config);
    server_address_ =
        absl::StrCat(server_config.host(), ":", server_config.port());
    return absl::OkStatus();
  }

  Status SetUpClient() {
    return client_launcher_.SetUp(absl::GetFlag(FLAGS_client_enclave_path),
                                  config_, kClientEnclaveName);
  }

  EnclaveManager *enclave_manager_;
  EnclaveTestLauncher client_launcher_;
  EnclaveClient *age_client_;
  std::unique_ptr<SgxInfrastructuralEnclaveManager> sgx_infra_enclave_manager_;
  EnclaveAssertionAuthorityConfig sgx_age_remote_config_;
  std::string server_address_;
};

TEST_F(SgxAgeRemoteServerEnclaveTest,
       BidirectionalAuthenticatedConnectionSucceeds) {
  constexpr char kMessage[] = "WFH: tired of social distancing";
  EnclaveInput input;
  EnclaveOutput output;
  ClientEnclaveInput *client_input =
      input.MutableExtension(client_enclave_input);
  client_input->add_self_grpc_creds_options(
      SGX_AGE_REMOTE_GRPC_CREDENTIALS_OPTIONS);
  client_input->add_peer_grpc_creds_options(
      SGX_AGE_REMOTE_GRPC_CREDENTIALS_OPTIONS);
  client_input->set_server_address(server_address_);
  client_input->set_rpc_input(kMessage);
  ASYLO_ASSERT_OK(client_launcher_.Run(input, &output));
  EXPECT_EQ(output.GetExtension(rpc_result),
            test::MessengerServer1::ResponseString(kMessage));
}

TEST_F(SgxAgeRemoteServerEnclaveTest, ServerAuthenticatedConnectionSucceeds) {
  constexpr char kMessage[] = "WFH: I miss my desktop";
  const int kConnectionDeadline = absl::Seconds(10) / absl::Microseconds(1);

  ASYLO_ASSERT_OK(InitializeEnclaveAssertionVerifier(sgx_age_remote_config_));
  ASYLO_ASSERT_OK(InitializeEnclaveAssertionGenerator(
      GetNullAssertionAuthorityTestConfig()));

  auto channel = ::grpc::CreateChannel(
      server_address_,
      EnclaveChannelCredentials(PeerSgxAgeRemoteCredentialsOptions().Add(
          SelfNullCredentialsOptions())));
  ASSERT_TRUE(channel->WaitForConnected(
      gpr_time_add(gpr_now(GPR_CLOCK_REALTIME),
                   gpr_time_from_micros(kConnectionDeadline, GPR_TIMESPAN))));

  test::MessengerClient1 client(channel);

  EXPECT_THAT(client.Hello(kMessage),
              IsOkAndHolds(test::MessengerServer1::ResponseString(kMessage)));
}

TEST_F(SgxAgeRemoteServerEnclaveTest, ClientSideAuthorizationSucceeds) {
  constexpr char kMessage[] = "WFH: I miss my two monitors";

  EnclaveInput input;
  EnclaveOutput output;
  ClientEnclaveInput *client_input =
      input.MutableExtension(client_enclave_input);
  client_input->add_self_grpc_creds_options(NULL_GRPC_CREDENTIALS_OPTIONS);
  client_input->add_peer_grpc_creds_options(
      SGX_AGE_REMOTE_GRPC_CREDENTIALS_OPTIONS);
  client_input->set_server_address(server_address_);
  SgxIdentityExpectation server_identity_expectation;
  ASYLO_ASSERT_OK_AND_ASSIGN(server_identity_expectation,
                             ClientSideAuthEnclaveSgxIdentityExpectation());
  server_identity_expectation.mutable_reference_identity()
      ->mutable_machine_configuration()
      ->set_sgx_type(sgx::STANDARD);
  server_identity_expectation.mutable_match_spec()
      ->mutable_machine_configuration_match_spec()
      ->set_is_sgx_type_match_required(true);
  ASYLO_ASSERT_OK_AND_ASSIGN(
      *client_input->mutable_peer_acl()->mutable_expectation(),
      SerializeSgxIdentityExpectation(server_identity_expectation));
  client_input->set_rpc_input(kMessage);
  ASYLO_ASSERT_OK(client_launcher_.Run(input, &output));
  EXPECT_EQ(output.GetExtension(rpc_result),
            test::MessengerServer1::ResponseString(kMessage));
}

}  // namespace
}  // namespace asylo
