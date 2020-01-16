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

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/enclave_manager.h"
#include "asylo/examples/grpc_server/grpc_server_util.h"
#include "asylo/examples/grpc_server/translator_client.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/path.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

ABSL_FLAG(std::string, server_enclave_path, "",
          "The path to the server enclave to pass to the enclave loader");

ABSL_FLAG(bool, debug_enclave, true,
          "Whether to load the server as a debug enclave");

namespace examples {
namespace grpc_server {
namespace {

using asylo::IsOkAndHolds;
using asylo::StatusIs;

class GrpcServerTest : public ::testing::Test {
 public:
  static void SetUpTestSuite() {
    ASYLO_ASSERT_OK(
        asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions()));
  }

  void SetUp() override {
    ASSERT_NE(absl::GetFlag(FLAGS_server_enclave_path), "");
    server_port_ = 0;
  }

  void StartServer() {
    ASYLO_ASSERT_OK(LoadGrpcServerEnclave(
        absl::GetFlag(FLAGS_server_enclave_path), server_port_,
        absl::GetFlag(FLAGS_debug_enclave)));

    // Retrieve the server's port.
    ASYLO_ASSERT_OK_AND_ASSIGN(server_port_, GrpcServerEnclaveGetPort());
    ASSERT_NE(server_port_, 0);
  }

  void TearDown() override { ASYLO_ASSERT_OK(DestroyGrpcServerEnclave()); }

  // Sends a GetTranslation RPC to the server via the client. Returns
  // the same grpc::Status as the stub function call. If the RPC is successful,
  // returns the translated word, else returns a non-OK status.
  asylo::StatusOr<std::string> MakeRpc(const std::string &input_word) {
    std::unique_ptr<TranslatorClient> client;
    ASYLO_ASSIGN_OR_RETURN(client, TranslatorClient::Create(absl::StrCat(
                                       "localhost:", server_port_)));
    return client->GrpcGetTranslation(input_word);
  }

 private:
  int server_port_;
};

TEST_F(GrpcServerTest, KnownTranslations) {
  ASSERT_NO_FATAL_FAILURE(StartServer());

  EXPECT_THAT(MakeRpc("asylo"), IsOkAndHolds("sanctuary"));
  EXPECT_THAT(MakeRpc("istio"), IsOkAndHolds("sail"));
  EXPECT_THAT(MakeRpc("kubernetes"), IsOkAndHolds("helmsman"));
}

TEST_F(GrpcServerTest, UnknownTranslation) {
  ASSERT_NO_FATAL_FAILURE(StartServer());

  EXPECT_THAT(MakeRpc("orkut"), StatusIs(asylo::error::INVALID_ARGUMENT,
                                         "No known translation for \"orkut\""));
}

}  // namespace
}  // namespace grpc_server
}  // namespace examples
