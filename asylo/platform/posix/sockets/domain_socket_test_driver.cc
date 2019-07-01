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

#include <stdio.h>
#include <sys/stat.h>

#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "asylo/client.h"
#include "asylo/util/logging.h"
#include "asylo/platform/posix/sockets/socket_client.h"
#include "asylo/platform/posix/sockets/socket_server.h"
#include "asylo/platform/posix/sockets/socket_test.pb.h"
#include "asylo/platform/posix/sockets/socket_test_transmit.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"

namespace asylo {
namespace {

using ::testing::Lt;

// This number is set according to struct sockaddr_un that has 108 bytes in
// its |sun_path| member.
constexpr int kMaxSocketNameLen = 108;

class DomainSocketDriver : public EnclaveTest {
 protected:
  // Builds an enclave input from the given parameters..
  EnclaveInput BuildEnclaveInput(const SocketTestInput::SocketAction &action,
                                 const std::string &socket_name,
                                 bool use_path_len) {
    SocketTestInput test_input;
    test_input.set_action(action);
    test_input.set_socket_name(socket_name);
    test_input.set_use_path_len(use_path_len);

    EnclaveInput ret;
    *ret.MutableExtension(socket_test_input) = test_input;

    return ret;
  }

  // Prepares unix domain socket
  std::string GetServerSocket(std::string sub_path) {
    std::string server_socket =
        absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir), sub_path);

    // Adds check of file path length here to make sure we provide a file path
    // within the limit of UNIX domain socket. When |FLAGS_test_tmpdir| is too
    // long, "/tmp" is selected if it exits and the user has r+w permission on
    // it. If we can not provide a proper file for the test, the test just
    // fails.
    if (server_socket.length() >= kMaxSocketNameLen) {
      struct stat stat_buf;
      EXPECT_TRUE(!stat("/tmp", &stat_buf) && S_ISDIR(stat_buf.st_mode) &&
                  (stat_buf.st_mode & S_IRUSR) && (stat_buf.st_mode & S_IWUSR));
      server_socket = absl::StrCat("/tmp", sub_path);
    }
    EXPECT_THAT(server_socket.length(), Lt(kMaxSocketNameLen));
    LOG(INFO) << "Cleaning up socket file if present, server_socket = "
              << server_socket;
    int res = remove(server_socket.c_str());
    if (res != 0) {
      LOG(INFO) << "remove failed";
    }
    return server_socket;
  }

  // Sets up UNIX domain-socket server thread outside enclave.
  static void AppServerSetup(SocketServer *app_socket_server,
                             const std::string &app_server_socket,
                             bool use_path_len) {
    EXPECT_THAT(app_socket_server->ServerSetup(app_server_socket, use_path_len),
                IsOk());
  }

  // Runs UNIX domain-socket server thread outside enclave.
  static void AppServerThread(SocketServer *app_socket_server) {
    EXPECT_THAT(app_socket_server->ServerAccept(), IsOk());
    EXPECT_THAT(ServerTransmit(app_socket_server), IsOk());
  }

  // Runs UNIX domain-socket client thread outside enclave.
  static void AppClientThread(const std::string &enc_server_socket,
                              bool use_path_len) {
    SocketClient app_socket_client;
    EXPECT_THAT(
        app_socket_client.ClientSetup(enc_server_socket, nullptr, use_path_len),
        IsOk());
    EXPECT_THAT(ClientTransmit(&app_socket_client), IsOk());
  }
};

// Tests UNIX domain-socket ClientSetup, Read and Write functions of
// SocketClient object inside enclave. Tests UNIX domain-socket ServerSetup,
// Read and Write functions of SocketClient object outside enclave.
TEST_F(DomainSocketDriver, EnclaveClientTestWithUsePathLenFalse) {
  std::string app_server_socket = GetServerSocket("/app_server_socket");
  SocketServer app_socket_server;
  AppServerSetup(&app_socket_server, app_server_socket, /*use_path_len=*/false);
  std::thread app_server_thread(&AppServerThread, &app_socket_server);
  EnclaveInput enclave_input = BuildEnclaveInput(
      SocketTestInput::RUNCLIENT, app_server_socket, /*use_path_len=*/false);
  EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());
  app_server_thread.join();
}

// Tests UNIX domain-socket ClientSetup, Read and Write functions of
// SocketClient object inside enclave. Tests UNIX domain-socket ServerSetup,
// Read and Write functions of SocketClient object outside enclave.
TEST_F(DomainSocketDriver, EnclaveClientTestWithUsePathLenTrue) {
  std::string app_server_socket = GetServerSocket("/app_server_socket");
  SocketServer app_socket_server;
  AppServerSetup(&app_socket_server, app_server_socket, /*use_path_len=*/true);
  std::thread app_server_thread(&AppServerThread, &app_socket_server);
  EnclaveInput enclave_input = BuildEnclaveInput(
      SocketTestInput::RUNCLIENT, app_server_socket, /*use_path_len=*/true);
  EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());
  app_server_thread.join();
}

// Tests UNIX domain-socket ServerSetup, Read and Write functions of
// SocketClient object inside enclave. Tests UNIX domain-socket ClientSetup,
// Read and Write functions of SocketClient object outside enclave.
TEST_F(DomainSocketDriver, EnclaveServerTestWithUsePathLenTrue) {
  std::string enc_server_socket = GetServerSocket("/enc_server_socket");
  EnclaveInput enclave_input = BuildEnclaveInput(
      SocketTestInput::INITSERVER, enc_server_socket, /*use_path_len=*/true);
  EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());
  std::thread app_client_thread(&AppClientThread, enc_server_socket,
                                /*use_path_len=*/true);
  enclave_input = BuildEnclaveInput(SocketTestInput::RUNSERVER,
                                    enc_server_socket, /*use_path_len=*/true);
  EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());
  app_client_thread.join();
}

// Tests UNIX domain-socket ServerSetup, Read and Write functions of
// SocketClient object inside enclave. Tests UNIX domain-socket ClientSetup,
// Read and Write functions of SocketClient object outside enclave.
TEST_F(DomainSocketDriver, EnclaveServerTestWithUsePathLenFalse) {
  std::string enc_server_socket = GetServerSocket("/enc_server_socket");
  EnclaveInput enclave_input =
      BuildEnclaveInput(SocketTestInput::INITSERVER, enc_server_socket, false);
  EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());
  std::thread app_client_thread(&AppClientThread, enc_server_socket,
                                /*use_path_len=*/false);
  enclave_input = BuildEnclaveInput(SocketTestInput::RUNSERVER,
                                    enc_server_socket, /*use_path_len=*/false);
  EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());
  app_client_thread.join();
}

}  // namespace
}  // namespace asylo
