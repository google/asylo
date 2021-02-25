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

#ifndef ASYLO_UTIL_REMOTE_GRPC_SERVER_MAIN_WRAPPER_H_
#define ASYLO_UTIL_REMOTE_GRPC_SERVER_MAIN_WRAPPER_H_

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/remote/util/grpc_credential_builder.h"
#include "asylo/util/remote/process_main_wrapper.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server_builder.h"

using ::asylo::primitives::GrpcCredentialBuilder;

namespace asylo {

// Specialized process wrapper template for gRPC server.
// Usage pattern:
//
// ABSL_FLAG(int32_t port, 1234, "...");
// class ServerImpl {
//  public:
//   static ::asylo::StatusOr<std::unique_ptr<ServerImpl>> Create(
//       ::grpc::ServerBuilder *builder,
//       arguments) {
//     auto server = absl::WrapUnique(new ServerImpl(arguments));
//     builder->RegisterServices(server->service_1_.get());
//     builder->RegisterServices(server->service_2_.get());
//     ...
//     return server;
//   }
//  private:
//   ServerImpl(arguments)
//       : service_1_(absl::make_unique<Service1>()),
//         service_2_(absl::make_unique<Service2>()) {
//     ...
//   }
//   ...
//   std::unique_ptr<Service1> service_1_;
//   std::unique_ptr<Service2> service_2_;
//   ...
// };
//
// int main(int argc, char *argv[]) {
//   absl::ParseCommandLine(argc, argv);
//   ProcessMainWrapper<GrpcServerMainWrapper<ServerImpl>>::RunUntilTerminated(
//       absl::GetFlag(FLAGS_port),
//       ::grpc::InsecureServerCredentials();
//       arguments to be passed to Create);
// }
template <typename T>
class GrpcServerMainWrapper {
 public:
  template <typename... Args>
  static StatusOr<std::unique_ptr<GrpcServerMainWrapper<T>>> Create(
      int port, Args &&...args) {
    // Create server.
    ::grpc::ServerBuilder builder;
    std::unique_ptr<T> server;
    ASYLO_ASSIGN_OR_RETURN(server,
                           T::Create(&builder, std::forward<Args>(args)...));

    // Create gRPC wrapped server instance.
    auto wrapper =
        absl::WrapUnique(new GrpcServerMainWrapper<T>(std::move(server)));

    // All services will be available on the same port.
    const std::string address = absl::StrCat("[::]:", port);
    LOG(INFO) << "Server start on " << address;

    // Create Credentials if they are not already set.
    std::shared_ptr<::grpc::ServerCredentials> server_credentials;
    ASYLO_ASSIGN_OR_RETURN(server_credentials,
                           GrpcCredentialBuilder::BuildServerCredentials());

    // Listen to the specified or auto-assigned port.
    builder.AddListeningPort(address, server_credentials, &wrapper->port_);

    // Launch server.
    wrapper->grpc_server_ = builder.BuildAndStart();

    // Communicate port back, if assigned automatically.
    LOG(INFO) << "Server started on " << address << " port=" << wrapper->port_;
    if (port == 0) {
      int bytes = write(STDOUT_FILENO, &wrapper->port_, sizeof(wrapper->port_));
      if (bytes != sizeof(wrapper->port_)) {
        return absl::InternalError("Failure to communicate port");
      }
    }
    return std::move(wrapper);
  }

  ~GrpcServerMainWrapper() = default;

  void Kill(int signum) {
    grpc_server_->Shutdown();
  }

  void Wait() { grpc_server_->Wait(); }

  int port() const { return port_; }

 private:
  explicit GrpcServerMainWrapper<T>(std::unique_ptr<T> server)
      : server_(std::move(server)) {}

  const std::unique_ptr<T> server_;
  int port_ = 0;
  std::unique_ptr<::grpc::Server> grpc_server_;
};

}  // namespace asylo

#endif  // ASYLO_UTIL_REMOTE_GRPC_SERVER_MAIN_WRAPPER_H_
