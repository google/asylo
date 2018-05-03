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

#ifndef ASYLO_GRPC_UTIL_ENCLAVE_SERVER_H_
#define ASYLO_GRPC_UTIL_ENCLAVE_SERVER_H_

#include <memory>
#include <string>

#include "grpcpp/security/server_credentials.h"
#include "grpcpp/server.h"
#include "grpcpp/server_builder.h"
#include "absl/synchronization/mutex.h"
#include "asylo/grpc/util/enclave_server.pb.h"
#include "asylo/trusted_application.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Enclave for hosting a gRPC service.
template <typename ServiceT>
class EnclaveServer final : public TrustedApplication {
 public:
  EnclaveServer(std::unique_ptr<ServiceT> service,
                std::shared_ptr<::grpc::ServerCredentials> credentials)
      : service_{std::move(service)}, credentials_{credentials} {}
  ~EnclaveServer() = default;

  // Required functions for TrustedApplication.
  Status Initialize(const EnclaveConfig &config) {
    const ServerConfig &config_server_proto =
        config.GetExtension(server_config);
    address_ = config_server_proto.address();
    LOG(INFO) << "Set address to: " << address_;
    return Status::OkStatus();
  }

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    return RunServer();
  }

  Status Finalize(const EnclaveFinal &enclave_final) {
    return FinalizeServer();
  }

 private:
  // Initializes an gRPC server. If the server is already initialized, returns
  // ALREADY_EXISTS.
  Status InitializeServer() LOCKS_EXCLUDED(server_mutex_) {
    // Ensure that the server is only created and initialized once.
    absl::MutexLock lock(&server_mutex_);
    if (server_) {
      return Status(error::GoogleError::ALREADY_EXISTS,
                    "Server is already started");
    }

    StatusOr<std::unique_ptr<::grpc::Server>> server_result = CreateServer();
    if (!server_result.ok()) {
      return server_result.status();
    }

    server_ = std::move(server_result.ValueOrDie());
    return Status::OkStatus();
  }

  // Runs the gRPC server. If the server is already running an error is
  // returned.
  Status RunServer() {
    Status status = InitializeServer();
    if (!status.ok()) {
      return status;
    }

    LOG(INFO) << "Server is listening on " << address_;

    // Block until process is killed or Shutdown() is called.
    server_->Wait();
    return Status::OkStatus();
  }

  // Finalizes the gRPC server by calling ::gprc::Server::Shutdown().
  Status FinalizeServer() LOCKS_EXCLUDED(server_mutex_) {
    absl::MutexLock lock(&server_mutex_);
    if (server_) {
      LOG(INFO) << "Shutting down...";
      server_->Shutdown();
      server_ = nullptr;
    }
    return Status::OkStatus();
  }

  // Creates a gRPC server that hosts service_ on address_ with credentials_.
  StatusOr<std::unique_ptr<::grpc::Server>> CreateServer() {
    ::grpc::ServerBuilder builder;
    builder.AddListeningPort(address_, credentials_);
    if (!service_.get()) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "service_ cannot be nullptr");
    }
    builder.RegisterService(service_.get());
    std::unique_ptr<::grpc::Server> server = builder.BuildAndStart();
    if (!server) {
      return Status(error::GoogleError::INTERNAL, "Failed to start server");
    }
    return std::move(server);
  }

  // Guards the |server_| member.
  absl::Mutex server_mutex_;

  // A gRPC server hosting |messenger_|.
  std::unique_ptr<::grpc::Server> server_ GUARDED_BY(server_mutex);

  std::string address_;
  std::unique_ptr<ServiceT> service_;
  std::shared_ptr<::grpc::ServerCredentials> credentials_;
};

}  // namespace asylo

#endif  // ASYLO_GRPC_UTIL_ENCLAVE_SERVER_H_
