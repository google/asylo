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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/enclave.pb.h"
#include "asylo/grpc/util/enclave_server.pb.h"
#include "asylo/test/grpc/client_enclave.pb.h"
#include "asylo/test/grpc/messenger_server_impl.h"
#include "asylo/test/util/enclave_test_launcher.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

DEFINE_string(client_enclave_path, "", "Path to client enclave");
DEFINE_string(server_enclave_path, "", "Path to server enclave");

constexpr char kName[] = "Mellanie Rescorai";
constexpr char kLocalAttestationDomain[] = "A unique attestation domain";

// A test for gRPC communication between two enclaves.
//
// This test expects the enclave paths to be passed in through the
// --client_enclave_path and --server_enclave_path flags.
class EnclaveCommunicationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    EnclaveConfig config;
    if (!FLAGS_test_tmpdir.empty()) {
      config.mutable_logging_config()->set_log_directory(FLAGS_test_tmpdir);
    }

    // The client and server must have the same local attestation domain in
    // order for SGX local attestation to work.
    config.mutable_host_config()->set_local_attestation_domain(
        kLocalAttestationDomain);

    ASSERT_THAT(SetUpServer(config), IsOk());
    ASSERT_THAT(SetUpClient(config), IsOk());
  }

  Status SetUpServer(EnclaveConfig config) {
    // Use port auto-selection for the server's address.
    ServerConfig *server_config = config.MutableExtension(server_input_config);
    server_config->set_host("[::1]");
    server_config->set_port(0);

    ASYLO_RETURN_IF_ERROR(server_launcher_.SetUp(FLAGS_server_enclave_path,
                                                 config, "/grpc/server"));

    // Get the gRPC server's address.
    EnclaveOutput output;
    ASYLO_RETURN_IF_ERROR(
        server_launcher_.mutable_client()->EnterAndRun(/*input=*/{}, &output));

    if (!output.HasExtension(server_output_config)) {
      return Status(error::GoogleError::INTERNAL,
                    "EnclaveServer did not return a server_output_config");
    }

    const ServerConfig &final_server_config =
        output.GetExtension(server_output_config);
    server_address_ = absl::StrCat(final_server_config.host(), ":",
                                   final_server_config.port());

    return Status::OkStatus();
  }

  Status SetUpClient(const EnclaveConfig &config) {
    ASYLO_RETURN_IF_ERROR(client_launcher_.SetUp(FLAGS_client_enclave_path,
                                                 config, "/grpc/client"));
    grpc_client_enclave_ = client_launcher_.mutable_client();
    return Status::OkStatus();
  }

  void TearDown() override {
    EnclaveFinal enclave_final;
    // Finalize both enclaves, even if tear down fails for the first one.
    EXPECT_THAT(
        client_launcher_.TearDown(enclave_final, /*skipTearDown=*/false),
        IsOk());
    EXPECT_THAT(
        server_launcher_.TearDown(enclave_final, /*skipTearDown=*/false),
        IsOk());
  }

  EnclaveTestLauncher client_launcher_;
  EnclaveTestLauncher server_launcher_;
  EnclaveClient *grpc_client_enclave_;
  std::string server_address_;
};

TEST_F(EnclaveCommunicationTest, SimpleSynchronousRpc) {
  EnclaveInput input;
  input.SetExtension(server_address, server_address_);
  input.SetExtension(rpc_input, kName);
  EnclaveOutput output;
  ASSERT_THAT(grpc_client_enclave_->EnterAndRun(input, &output), IsOk());
  EXPECT_EQ(output.GetExtension(rpc_result),
            test::MessengerServer1::ResponseString(kName));
}


}  // namespace
}  // namespace asylo
