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

#include <fcntl.h>
#include <sys/stat.h>

#include <cstdint>
#include <string>
#include <tuple>
#include <vector>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/enclave_manager.h"
#include "asylo/examples/secure_grpc/grpc_client_util.h"
#include "asylo/examples/secure_grpc/grpc_server_util.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

ABSL_FLAG(std::string, server_enclave_path, "",
          "The path to the server enclave to pass to the enclave loader");

ABSL_FLAG(std::string, client_enclave_path, "",
          "The path to the client enclave to pass to the enclave loader");

ABSL_FLAG(std::string, acl_isvprodid_2_path, "",
          "Path to acl_isvprodid_2.textproto");

ABSL_FLAG(std::string, acl_isvprodid_3_path, "",
          "Path to acl_isvprodid_3.textproto");

ABSL_FLAG(std::string, acl_non_debug_path, "",
          "Path to acl_non_debug_2.textproto");

ABSL_FLAG(bool, debug_enclave, true, "Whether to debug enclaves");

constexpr char kAuthorizationFailureMessage[] =
    "Peer is unauthorized for GetTranslation: ACL failed to match";

namespace examples {
namespace secure_grpc {
namespace {

using asylo::IsOkAndHolds;
using asylo::StatusIs;
using ::testing::AllOf;
using ::testing::HasSubstr;

class GrpcServerTest : public ::testing::Test {
 public:
  static void SetUpTestSuite() {
    ASYLO_ASSERT_OK(
        asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions()));
  }

  void SetUp() override {
    ASSERT_NE(absl::GetFlag(FLAGS_server_enclave_path), "");
    ASSERT_NE(absl::GetFlag(FLAGS_client_enclave_path), "");
    ASSERT_NE(absl::GetFlag(FLAGS_acl_isvprodid_2_path), "");
    ASSERT_NE(absl::GetFlag(FLAGS_acl_isvprodid_3_path), "");
    ASSERT_NE(absl::GetFlag(FLAGS_acl_non_debug_path), "");
    server_port_ = 0;
  }

  void StartServer(const std::string &acl_path) {
    int fd = open(acl_path.c_str(), O_RDONLY);
    ASSERT_GT(fd, -1) << strerror(errno);
    google::protobuf::io::FileInputStream stream(fd);
    stream.SetCloseOnDelete(true);

    asylo::SgxIdentityExpectation expectation;
    ASSERT_TRUE(google::protobuf::TextFormat::Parse(&stream, &expectation));

    ASYLO_ASSERT_OK(LoadGrpcServerEnclave(
        absl::GetFlag(FLAGS_server_enclave_path), server_port_, expectation,
        absl::GetFlag(FLAGS_debug_enclave)));

    // Retrieve the server's port.
    ASYLO_ASSERT_OK_AND_ASSIGN(server_port_, GrpcServerEnclaveGetPort());
    ASSERT_NE(server_port_, 0);
  }

  void TearDown() override { ASYLO_ASSERT_OK(DestroyGrpcServerEnclave()); }

  asylo::Status LoadGrpcClientEnclave() {
    return examples::secure_grpc::LoadGrpcClientEnclave(
        absl::GetFlag(FLAGS_client_enclave_path),
        absl::GetFlag(FLAGS_debug_enclave));
  }

  // Sends a GetTranslation RPC to the server via the client enclave. Returns
  // the same grpc::Status as the stub function call. If the RPC is successful,
  // returns the translated word, else returns a non-OK status.
  asylo::StatusOr<std::string> MakeRpc(const std::string &input_word) {
    return GrpcClientEnclaveGetTranslation(
        absl::StrCat("localhost:", server_port_), input_word);
  }

 private:
  int server_port_;
};

TEST_F(GrpcServerTest, AuthorizationSuccess) {
  ASSERT_NO_FATAL_FAILURE(
      StartServer(absl::GetFlag(FLAGS_acl_isvprodid_2_path)));

  ASYLO_ASSERT_OK(LoadGrpcClientEnclave());

  EXPECT_THAT(MakeRpc("asylo"), IsOkAndHolds("sanctuary"));
  EXPECT_THAT(MakeRpc("istio"), IsOkAndHolds("sail"));
  EXPECT_THAT(MakeRpc("kubernetes"), IsOkAndHolds("helmsman"));

  ASYLO_ASSERT_OK(DestroyGrpcClientEnclave());
}

TEST_F(GrpcServerTest, Isvprodid3AuthorizationFailure) {
  ASSERT_NO_FATAL_FAILURE(
      StartServer(absl::GetFlag(FLAGS_acl_isvprodid_3_path)));

  ASYLO_ASSERT_OK(LoadGrpcClientEnclave());
  EXPECT_THAT(MakeRpc("asylo"),
              StatusIs(asylo::error::PERMISSION_DENIED,
                       AllOf(HasSubstr(kAuthorizationFailureMessage),
                             HasSubstr("ISVPRODID"))));
  ASYLO_ASSERT_OK(DestroyGrpcClientEnclave());
}

TEST_F(GrpcServerTest, NonDebugAuthorizationFailure) {
  ASSERT_NO_FATAL_FAILURE(StartServer(absl::GetFlag(FLAGS_acl_non_debug_path)));

  ASYLO_ASSERT_OK(LoadGrpcClientEnclave());
  EXPECT_THAT(MakeRpc("asylo"),
              StatusIs(asylo::error::PERMISSION_DENIED,
                       AllOf(HasSubstr(kAuthorizationFailureMessage),
                             HasSubstr("DEBUG"))));
  ASYLO_ASSERT_OK(DestroyGrpcClientEnclave());
}

}  // namespace
}  // namespace secure_grpc
}  // namespace examples
