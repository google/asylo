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

#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/client.h"
#include "asylo/platform/posix/sockets/socket_client.h"
#include "asylo/platform/posix/sockets/socket_server.h"
#include "asylo/platform/posix/sockets/socket_test.pb.h"
#include "asylo/platform/posix/sockets/socket_test_transmit.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

class Inet6SocketDriver : public EnclaveTest {
 protected:
  // Builds enclave input from the given parameters.
  EnclaveInput BuildEnclaveInput(const SocketTestInput::SocketAction &action,
                                 int server_port = 0) {
    SocketTestInput test_input;
    test_input.set_action(action);
    test_input.set_server_port(server_port);

    EnclaveInput ret;
    *ret.MutableExtension(socket_test_input) = test_input;

    return ret;
  }

  // Sets up INET6 socket server thread outside enclave.
  static void AppServerSetup(SocketServer *app_socket_server) {
    EXPECT_THAT(app_socket_server->ServerSetup(), IsOk());
  }

  // Runs INET6 socket server thread outside enclave.
  static void AppServerThread(SocketServer *app_socket_server) {
    EXPECT_THAT(app_socket_server->ServerAccept(), IsOk());
    EXPECT_THAT(ServerTransmit(app_socket_server), IsOk());
  }

  // Runs INET6 socket client thread outside enclave.
  static void AppClientThread(int enc_server_port) {
    SocketClient app_socket_client;
    EXPECT_TRUE(app_socket_client
                    .ClientSetup(kLocalIpv6AddrStr, enc_server_port, nullptr)
                    .ok());
    EXPECT_THAT(ClientTransmit(&app_socket_client), IsOk());
  }
};
// Tests INET6 socket ClientSetup, Read and Write functions of SocketClient
// object inside enclave. Tests INET6 socket ServerSetup, Read and Write
// functions of SocketClient object outside enclave.
TEST_F(Inet6SocketDriver, EnclaveClientTest) {
  SocketServer app_socket_server;
  AppServerSetup(&app_socket_server);
  int app_server_port = app_socket_server.GetPort();
  ASSERT_NE(app_server_port, -1);
  std::thread app_server_thread(&AppServerThread, &app_socket_server);
  EnclaveInput enclave_input =
      BuildEnclaveInput(SocketTestInput::RUNCLIENT, app_server_port);
  EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());
  app_server_thread.join();
}

// Tests INET6 socket ServerSetup, Read and Write functions of SocketClient
// object inside enclave. Tests INET6 socket ClientSetup, Read and Write
// functions of SocketClient object outside enclave.
TEST_F(Inet6SocketDriver, EnclaveServerTest) {
  EnclaveInput enclave_input = BuildEnclaveInput(SocketTestInput::INITSERVER);
  EnclaveOutput enclave_output;
  EXPECT_THAT(client_->EnterAndRun(enclave_input, &enclave_output), IsOk());
  int enc_server_port =
      enclave_output.GetExtension(socket_test_output).server_port();
  ASSERT_NE(enc_server_port, -1);
  std::thread app_client_thread(&AppClientThread, enc_server_port);
  enclave_input =
      BuildEnclaveInput(SocketTestInput::RUNSERVER, enc_server_port);
  EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());
  app_client_thread.join();
}

}  // namespace
}  // namespace asylo
