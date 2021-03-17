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

#include <netinet/in.h>

#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/platform/posix/sockets/socket_client.h"
#include "asylo/platform/posix/sockets/socket_server.h"
#include "asylo/platform/posix/sockets/socket_test.pb.h"
#include "asylo/platform/posix/sockets/socket_test_transmit.h"
#include "asylo/test/util/enclave_test_application.h"

namespace asylo {

class Inet6SocketTest : public EnclaveTestCase {
 public:
  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    if (!input.HasExtension(socket_test_input)) {
      return absl::InvalidArgumentError("Missing inet6 socket_test_input");
    }
    SocketTestInput test_input = input.GetExtension(socket_test_input);
    if (!test_input.has_action() || !test_input.has_server_port()) {
      return absl::InvalidArgumentError(
          "inet6 socket_test_input is incomplete");
    }
    SocketTestInput::SocketAction enc_command = test_input.action();
    int server_port = test_input.server_port();

    if (enc_command == SocketTestInput::INITSERVER) {
      SocketTestOutput *test_output = nullptr;
      if (output) {
        test_output = output->MutableExtension(socket_test_output);
      }
      return EncSetupServer(server_port, test_output);
    } else if (enc_command == SocketTestInput::RUNSERVER) {
      return EncRunServer();
    } else if (enc_command == SocketTestInput::RUNCLIENT) {
      return EncRunClient(server_port);
    } else {
      return absl::InvalidArgumentError(
          "Unrecognized command for inet6 socket test");
    }
  }

 private:
  // Runs INET6 socket server inside enclave.
  Status EncSetupServer(int enc_server_port, SocketTestOutput *output) {
    if (!enc_socket_server_.ServerSetup(enc_server_port).ok()) {
      return absl::InternalError("Server setup failed");
    }
    if (output) {
      output->set_server_port(enc_socket_server_.GetPort());
    }
    return absl::OkStatus();
  }

  // Runs INET6 socket server inside enclave.
  Status EncRunServer() {
    if (!enc_socket_server_.ServerAccept().ok()) {
      return absl::InternalError("Server accept failed");
    }
    if (!ServerTransmit(&enc_socket_server_).ok()) {
      return absl::InternalError("Server transmit failed");
    }
    return absl::OkStatus();
  }

  // Runs INET6 socket client inside enclave.
  Status EncRunClient(int app_server_port) {
    SocketClient enc_socket_client;
    sockaddr_in6 app_server_sockaddr;
    if (!enc_socket_client
             .ClientSetup(kLocalIpv6AddrStr, app_server_port,
                          &app_server_sockaddr)
             .ok()) {
      return absl::InternalError("Client setup failed");
    }

    // Test getpeername() by ensuring its return value matches the server
    // address we just connected to.
    struct sockaddr_storage peer_sockaddr;
    socklen_t peer_sockaddr_len = sizeof(peer_sockaddr);
    Status retval = enc_socket_client.GetPeername(
        reinterpret_cast<struct sockaddr *>(&peer_sockaddr),
        &peer_sockaddr_len);
    if (!retval.ok()) {
      return retval;
    }
    if (peer_sockaddr_len != sizeof(sockaddr_in6)) {
      LOG(ERROR) << "peer addrlen " << peer_sockaddr_len
                 << " doesn't match server addr len " << sizeof(sockaddr_in6);
      return absl::InternalError("getpeername failure 1");
    }
    if (memcmp(&peer_sockaddr, &app_server_sockaddr, sizeof(sockaddr_in6))) {
      LOG(ERROR) << "peer addr doesn't match server addr!";
      return absl::InternalError("getpeername failure 2");
    }

    if (!ClientTransmit(&enc_socket_client).ok()) {
      return absl::InternalError("Client transmit failed");
    }
    return absl::OkStatus();
  }

  SocketServer enc_socket_server_;
};
TrustedApplication *BuildTrustedApplication() { return new Inet6SocketTest; }

}  // namespace asylo
