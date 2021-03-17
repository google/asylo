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

#include <sys/un.h>

#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/platform/posix/sockets/socket_client.h"
#include "asylo/platform/posix/sockets/socket_server.h"
#include "asylo/platform/posix/sockets/socket_test.pb.h"
#include "asylo/platform/posix/sockets/socket_test_transmit.h"
#include "asylo/test/util/enclave_test_application.h"

namespace asylo {

class DomainSocketTest : public EnclaveTestCase {
 public:
  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    if (!input.HasExtension(socket_test_input)) {
      return absl::InvalidArgumentError("Missing domain socket test input");
    }
    SocketTestInput test_input = input.GetExtension(socket_test_input);
    if (!test_input.has_action() || !test_input.has_socket_name()) {
      return absl::InvalidArgumentError(
          "domain socket test input is incomplete");
    }
    SocketTestInput::SocketAction enc_command = test_input.action();
    std::string socket_name = test_input.socket_name();

    if (enc_command == SocketTestInput::INITSERVER) {
      return EncSetupServer(socket_name, test_input.use_path_len());
    } else if (enc_command == SocketTestInput::RUNSERVER) {
      return EncRunServer();
    } else if (enc_command == SocketTestInput::RUNCLIENT) {
      return EncRunClient(socket_name, test_input.use_path_len());
    } else {
      return absl::InvalidArgumentError(
          "Unrecognized command for domain socket test");
    }
  }

 private:
  // Sets up UNIX domain-socket server inside enclave.
  Status EncSetupServer(const std::string &socket_name, bool use_path_len) {
    if (!enc_socket_server_.ServerSetup(socket_name, use_path_len).ok()) {
      return absl::InternalError("Server setup failed");
    }
    return absl::OkStatus();
  }

  // Runs UNIX domain-socket server inside enclave.
  Status EncRunServer() {
    if (!enc_socket_server_.ServerAccept().ok()) {
      return absl::InternalError("Server accept failed");
    }
    if (!ServerTransmit(&enc_socket_server_).ok()) {
      return absl::InternalError("Server transmit failed");
    }
    return absl::OkStatus();
  }

  // Runs UNIX domain-socket client inside enclave.
  Status EncRunClient(const std::string &socket_name, bool use_path_len) {
    SocketClient enc_socket_client;
    sockaddr_un app_server_sockaddr;
    if (!enc_socket_client
             .ClientSetup(socket_name, &app_server_sockaddr, use_path_len)
             .ok()) {
      return absl::InternalError("Client setup failed");
    }

    // Test getpeername() by ensuring its return value matches the server
    // address we just connected to. Note that getpeername() on AF_UNIX sockets
    // only returns a family, not a path name.
    struct sockaddr_storage peer_sockaddr;
    socklen_t peer_sockaddr_len = sizeof(peer_sockaddr);
    Status retval = enc_socket_client.GetPeername(
        reinterpret_cast<struct sockaddr *>(&peer_sockaddr),
        &peer_sockaddr_len);
    if (!retval.ok()) {
      return retval;
    }
    sockaddr_un *peer_sockaddr_un = (sockaddr_un *)&peer_sockaddr;
    if (app_server_sockaddr.sun_family != peer_sockaddr_un->sun_family) {
      LOG(ERROR) << "peer addr is incorrect family";
      return absl::InternalError("getpeername failure 2");
    }

    if (!ClientTransmit(&enc_socket_client).ok()) {
      return absl::InternalError("Client transmit failed");
    }
    return absl::OkStatus();
  }

  SocketServer enc_socket_server_;
};
TrustedApplication *BuildTrustedApplication() { return new DomainSocketTest; }

}  // namespace asylo
