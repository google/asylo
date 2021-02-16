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

#ifndef ASYLO_GRPC_UTIL_GRPC_SERVER_LAUNCHER_H_
#define ASYLO_GRPC_UTIL_GRPC_SERVER_LAUNCHER_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "asylo/util/status.h"
#include "include/grpcpp/impl/codegen/service_type.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server.h"
#include "include/grpcpp/server_builder.h"

namespace asylo {

// The GrpcServerLauncher class is a helper class designed to simplify launching
// a gRPC server that hosts multiple services that listen on different ports.
// The expected usage of this class is as follows:
//   // Create a launcher instance.
//   GrpcServerLauncher launcher("my launcher");
//
//   // Register one or more services, ports, and credentials.
//   launcher.RegisterService(...);
//   launcher.RegisterService(...);
//   launcher.AddListeningPort(...);
//   launcher.AddListeningPort(...);
//   ...
//
//   // Start the server.
//   launcher.Start();
//
//   // Wait for the server to shut down. This ensures that the launcher does
//   // not get destroyed while the server is still running.
//   launcher.Wait();
//
// The Shutdown() method is expected to be called from another thread in
// response to some external event such as receipt of a signal or a special
// management-RPC invocation.
//
// The helper class adds some sanity checks to ensure that this general flow is
// followed. Specifically, the following usage patterns are not supported:
//    - Registering services or adding listening ports after the server has
//      started.
//    - Shutting down or waiting on a server before it has started.
//    - Shutting down the server twice.
//    - Waiting on the server after it has shut down.
//    - Attempting to start the server multiple times.
//    - Attempting to start the server after Shutdown() has been called.
//    - Performing any of the launcher operations while the launcher itself is
//      being desroyed.
//
//  Note that it is the responsibility of the caller to manage the lifetime of
//  the launcher object and making sure that the launcher object does not get
//  destroyed while the server is being launched/invoked/shut-down. Also, the
//  caller is responsible for shutting down the server before the launcher gets
//  destroyed. Keeping the server running while the launcher is being destroyed
//  may lead to unexpected/undesired behavior.
//
//  This class is thread-safe. The various methods of this class can be called
//  from different threads without leaving the class in an internally
//  inconsistent state. However, if callers do not follow the basic sanity
//  requirements described above, then they may get unexpected errors such as
//  failure to launch the server.
class GrpcServerLauncher {
 public:
  enum class State { NOT_LAUNCHED, LAUNCHED, TERMINATED };

  GrpcServerLauncher(std::string name)
      : name_{std::move(name)}, state_{State::NOT_LAUNCHED} {}

  // Registers a gRPC service with the server. Takes ownership of |service|.
  Status RegisterService(std::unique_ptr<::grpc::Service> service);

  // Adds a listening port and associated credentials to the server. If
  // |selected_port| is not nullptr, then populates this value with the port
  // used once the server is started (i.e. via a call to Start()). The value of
  // |selected_port| may be different from the port in |address| if |address|
  // specifies port 0, which indicates that gRPC should automatically select an
  // available port. In this case, the caller should examine the value of
  // |selected_port| after starting the server to determine the selected port.
  Status AddListeningPort(const std::string &address,
                          std::shared_ptr<::grpc::ServerCredentials> creds,
                          int *selected_port = nullptr);

  // Starts the gRPC server.
  Status Start();

  // Waits for server to shut down.
  Status Wait() const;

  // Shuts down the server started by this object.
  Status Shutdown();

  // Returns the current state of this object. The method is thread-safe,
  // guarantees that the object had reached a state that is completely
  // consistent with the returned value when the value was read. For example, if
  // this method returns State::LAUNCHED, then there is no way that the server_
  // member variable of the object could be set to nullptr or could be actively
  // being modified.
  State GetState();

 private:
  Status MakeStatus(absl::StatusCode code, const std::string &message) const {
    return Status(code, absl::StrCat("Server ", name_, ": ", message));
  }

  // Identifier for the server which is used for logging and debugging purposes.
  std::string name_;

  // Mutex to protect server_, state_, services_, and builder_.
  mutable absl::Mutex mu_;
  State state_;
  std::vector<std::unique_ptr<::grpc::Service>> services_;
  std::unique_ptr<::grpc::Server> server_;
  ::grpc::ServerBuilder builder_;
};

}  // namespace asylo

#endif  // ASYLO_GRPC_UTIL_GRPC_SERVER_LAUNCHER_H_
