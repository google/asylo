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

#include <sys/wait.h>
#include <iostream>
#include <memory>
#include <regex>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "asylo/examples/grpc_server/translator_server.grpc.pb.h"
#include "gflags/gflags.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/exec_tester.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"

DEFINE_string(enclave_path, "",
              "The path to the server enclave to pass to the enclave loader");

// The number of seconds to run the server for this test.
constexpr int kServerLifetime = 1;

// A regex matching the log message that contains the port.
constexpr char kPortMessageRegex[] = "Server started on port [0-9]+";

namespace examples {
namespace grpc_server {
namespace {

using asylo::IsOk;
using asylo::StatusIs;

// An ExecTester that scans stderr for the "Server started" log message from
// the gRPC server enclave. If it finds the startup message, it writes the
// server's port to an external buffer.
class ServerEnclaveExecTester : public asylo::experimental::ExecTester {
 public:
  ServerEnclaveExecTester(const std::vector<std::string> &args,
                          absl::Mutex *server_port_mutex, int *server_port)
        : ExecTester(args),
        server_port_found_(false),
        server_thread_state_mutex_(server_port_mutex),
        server_port_(server_port) {}

 protected:
  bool CheckLine(const std::string &line) override
      LOCKS_EXCLUDED(*server_thread_state_mutex_) {
    const std::regex port_message_regex(kPortMessageRegex);
    const std::regex port_regex("[0-9]+");

    // Check if the line matches kPortMessageRegex. If so, put the port number
    // in |*server_port_|.
    std::cmatch port_message_match;
    if (std::regex_search(line.c_str(), port_message_match,
                          port_message_regex)) {
      std::cmatch port_match;
      EXPECT_TRUE(std::regex_search(port_message_match.str().c_str(),
                                    port_match, port_regex))
          << absl::StrCat("Could not find port number in \"",
                          port_message_match.str(), "\"");
      server_port_found_ = true;
      absl::MutexLock lock(server_thread_state_mutex_);
      EXPECT_TRUE(absl::SimpleAtoi(port_match.str(), server_port_))
          << absl::StrCat("Could not convert \"", port_match.str(),
                          "\" to integer");
    }
    // Print the line back to stdout to help with debugging.
    std::cout << line << std::endl;
    return true;
  }

  bool FinalCheck(bool accumulated) override
      LOCKS_EXCLUDED(*server_thread_state_mutex_) {
    return accumulated && server_port_found_;
  }

  bool server_port_found_;
  absl::Mutex *server_thread_state_mutex_;
  int *server_port_ PT_GUARDED_BY(*server_thread_state_mutex_);
};

class GrpcServerTest : public ::testing::Test {
 public:
  // Spawns the enclave loader subprocess and waits for it to log the port
  // number. Fails if the log message is never seen.
  void SetUp() override LOCKS_EXCLUDED(server_thread_state_mutex_) {
    ASSERT_NE(FLAGS_enclave_path, "");

    const std::vector<std::string> argv({
        asylo::experimental::ExecTester::BuildSiblingPath(
            FLAGS_enclave_path, "grpc_server_host_loader"),
        absl::StrCat("--enclave_path=", FLAGS_enclave_path),
        absl::StrCat("--server_lifetime=", kServerLifetime),
    });

    server_port_found_ = false;

    // Set server_port_ to -1 and server_thread_finished_ to false so that
    // GetServerPort() knows when server_thread_ has either found the server
    // port log message or terminated.
    {
      absl::MutexLock lock(&server_thread_state_mutex_);
      server_thread_finished_ = false;
      server_port_ = -1;
    }

    // Run the server ExecTester in a separate thread.
    server_thread_ = absl::make_unique<std::thread>(
        [this](const std::vector<std::string> &argv) {
          ServerEnclaveExecTester server_runner(
              argv, &server_thread_state_mutex_, &server_port_);
          server_port_found_ =
              server_runner.Run(/*input=*/"", &server_exit_status_);
          absl::MutexLock lock(&server_thread_state_mutex_);
          server_thread_finished_ = true;
        },
        argv);

    // Wait until server_thread_ sets server_port_ or terminates.
    int port = GetServerPort();
    ASSERT_NE(port, -1)
        << "Server subprocess terminated without printing port log message";

    // Set up the client stub.
    std::shared_ptr<::grpc::ChannelCredentials> credentials =
        ::grpc::InsecureChannelCredentials();
    std::string server_address = absl::StrCat("dns:///localhost:", port);
    std::shared_ptr<::grpc::Channel> channel =
        ::grpc::CreateChannel(server_address, credentials);
    stub_ = Translator::NewStub(channel);
  }

  void TearDown() override {
    server_thread_->join();
    ASSERT_TRUE(server_port_found_);
    ASSERT_TRUE(WIFEXITED(server_exit_status_))
        << (WIFSIGNALED(server_exit_status_)
                ? absl::StrCat("Server subprocess killed by signal ",
                               WTERMSIG(server_exit_status_))
                : "Server subprocess ended abnormally");
    EXPECT_EQ(WEXITSTATUS(server_exit_status_), 0)
        << absl::StrCat("Server subprocess exited with non-zero status ",
                        WEXITSTATUS(server_exit_status_));
  }

  // Sends a GetTranslation RPC to the server. Returns the same grpc::Status as
  // the stub function call. If the RPC is successful, then sets
  // |*translated_word| to the received translation.
  asylo::Status MakeRpc(const std::string &input_word, std::string *translated_word) {
    ::grpc::ClientContext context;
    GetTranslationRequest request;
    GetTranslationResponse response;

    request.set_input_word(input_word);
    ::grpc::Status status = stub_->GetTranslation(&context, request, &response);
    if (status.ok()) {
      *translated_word = response.translated_word();
    }

    return asylo::Status(status);
  }

 private:
  // Waits for server_thread_ to either set server_port_ or terminate, then
  // returns the value of server_port_.
  int GetServerPort() LOCKS_EXCLUDED(server_thread_state_mutex_) {
    std::tuple<int *, bool *> args =
        std::make_tuple(&server_port_, &server_thread_finished_);
    server_thread_state_mutex_.LockWhen(absl::Condition(
        +[](std::tuple<int *, bool *> *args) {
          int *server_port = std::get<0>(*args);
          bool *server_thread_finished = std::get<1>(*args);
          return *server_port != -1 || *server_thread_finished;
        },
        &args));
    int result = server_port_;
    server_thread_state_mutex_.Unlock();
    return result;
  }

  std::unique_ptr<std::thread> server_thread_;

  // These values don't need to be guarded by a mutex because they are not read
  // until the ExecTester thread (which writes to them) has been joined.
  bool server_port_found_;
  int server_exit_status_;

  absl::Mutex server_thread_state_mutex_;
  bool server_thread_finished_ GUARDED_BY(server_thread_state_mutex_);
  int server_port_ GUARDED_BY(server_thread_state_mutex_);

  std::unique_ptr<Translator::Stub> stub_;
};

TEST_F(GrpcServerTest, AsyloTranslatesToSanctuary) {
  std::string asylo_translation;
  ASSERT_THAT(MakeRpc("asylo", &asylo_translation), IsOk());
  EXPECT_EQ(asylo_translation, "sanctuary");
}

TEST_F(GrpcServerTest, IstioTranslatesToSail) {
  std::string istio_translation;
  ASSERT_THAT(MakeRpc("istio", &istio_translation), IsOk());
  EXPECT_EQ(istio_translation, "sail");
}

TEST_F(GrpcServerTest, KubernetesTranslatesToHelmsman) {
  std::string kubernetes_translation;
  ASSERT_THAT(MakeRpc("kubernetes", &kubernetes_translation), IsOk());
  EXPECT_EQ(kubernetes_translation, "helmsman");
}

TEST_F(GrpcServerTest, OrkutTranslationNotFound) {
  std::string orkut_translation;
  asylo::Status status = MakeRpc("orkut", &orkut_translation);
  ASSERT_THAT(status, StatusIs(asylo::error::INVALID_ARGUMENT));
  EXPECT_EQ(status.error_message(), "No known translation for \"orkut\"");
}

}  // namespace
}  // namespace grpc_server
}  // namespace examples
