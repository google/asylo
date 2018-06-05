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

#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "asylo/util/logging.h"
#include "asylo/grpc/util/enclave_server.pb.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/impl/codegen/service_type.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server.h"
#include "include/grpcpp/server_builder.h"

namespace asylo {

// Enclave for hosting a gRPC service.
class EnclaveServer final : public TrustedApplication {
 public:
  EnclaveServer(std::unique_ptr<::grpc::Service> service,
                std::shared_ptr<::grpc::ServerCredentials> credentials)
      : running_{false},
        service_{std::move(service)},
        credentials_{credentials} {}
  ~EnclaveServer() = default;

  // From TrustedApplication.

  Status Initialize(const EnclaveConfig &config) {
    const ServerConfig &config_server_proto =
        config.GetExtension(server_input_config);
    host_ = config_server_proto.host();
    port_ = config_server_proto.port();
    LOG(INFO) << "Server configured with address: " << host_ << ":" << port_;
    return Status::OkStatus();
  }

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    switch (input.GetExtension(command)) {
      case ServerCommand::INITIALIZE_SERVER:
        return InitializeServer(output);
      case ServerCommand::RUN_SERVER:
        return RunServer();
      case ServerCommand::UNKNOWN:
        return Status(
            error::GoogleError::INVALID_ARGUMENT,
            absl::StrCat("Invalid command: ",
                         ServerCommand_Name(input.GetExtension(command))));
      default:
        return Status(
            error::GoogleError::INVALID_ARGUMENT,
            absl::StrCat("Unrecognized command: ",
                         ServerCommand_Name(input.GetExtension(command))));
    }
  }

  Status Finalize(const EnclaveFinal &enclave_final) {
    return FinalizeServer();
  }

 private:
  // Initializes a gRPC server, returning the server configuration in |output|.
  // If the server is already initialized, does not re-initialize it, but
  // returns the server's configuration in |output|.
  Status InitializeServer(EnclaveOutput *output) LOCKS_EXCLUDED(server_mutex_) {
    // Ensure that the server is only created and initialized once.
    absl::MutexLock lock(&server_mutex_);
    if (server_) {
      return GetServerAddress(output);
    }

    StatusOr<std::unique_ptr<::grpc::Server>> server_result = CreateServer();
    if (!server_result.ok()) {
      return server_result.status();
    }

    server_ = std::move(server_result.ValueOrDie());
    return GetServerAddress(output);
  }

  // Creates a gRPC server that hosts service_ on host_ and port_ with
  // credentials_.
  StatusOr<std::unique_ptr<::grpc::Server>> CreateServer()
      EXCLUSIVE_LOCKS_REQUIRED(server_mutex_) {
    int port;
    ::grpc::ServerBuilder builder;
    builder.AddListeningPort(absl::StrCat(host_, ":", port_), credentials_,
                             &port);
    if (!service_.get()) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "service_ cannot be nullptr");
    }
    builder.RegisterService(service_.get());
    std::unique_ptr<::grpc::Server> server = builder.BuildAndStart();
    if (!server) {
      return Status(error::GoogleError::INTERNAL, "Failed to start server");
    }
    port_ = port;
    return std::move(server);
  }

  // Gets the address of the hosted gRPC server and writes it to
  // server_output_config extension of |output|.
  Status GetServerAddress(EnclaveOutput *output)
      EXCLUSIVE_LOCKS_REQUIRED(server_mutex_) {
    ServerConfig *config = output->MutableExtension(server_output_config);
    config->set_host(host_);
    config->set_port(port_);
    return Status::OkStatus();
  }

  // Runs the gRPC server. The server must have been previously initialized.
  // Returns an error if the server is already running.
  Status RunServer() {
    {
      absl::MutexLock lock(&server_mutex_);
      if (!server_) {
        return Status(error::GoogleError::FAILED_PRECONDITION,
                      "Server has not been initialized");
      }

      if (running_) {
        return Status(error::GoogleError::INTERNAL,
                      "Server is already running");
      }
      running_ = true;
    }

    LOG(INFO) << "Server is listening on " << host_ << ":" << port_;

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

  // Guards state related to the gRPC server (|server_| and |port_|).
  absl::Mutex server_mutex_;

  // A gRPC server hosting |messenger_|.
  std::unique_ptr<::grpc::Server> server_ GUARDED_BY(server_mutex);

  // Indicates whether the server has been started.
  bool running_;

  // The host and port of the server's address.
  std::string host_;
  int port_;

  std::unique_ptr<::grpc::Service> service_;
  std::shared_ptr<::grpc::ServerCredentials> credentials_;
};

}  // namespace asylo

#endif  // ASYLO_GRPC_UTIL_ENCLAVE_SERVER_H_
