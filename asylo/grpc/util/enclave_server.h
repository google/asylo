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

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/grpc/util/enclave_server.pb.h"
#include "asylo/trusted_application.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/impl/codegen/service_type.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server.h"
#include "include/grpcpp/server_builder.h"

namespace asylo {

// Enclave for hosting a gRPC service.
//
// The gRPC service and credentials are configurable in the constructor.
//
// The server is initialized and started during Initialize(). Users of this
// class are expected to set the server's host and port in the EnclaveConfig
// provided to EnclaveManager::LoadEnclave() when loading their enclave.
//
// The Run() entry-point can be used to retrieve the server's host and port.
// The port may be different than the value provided at enclave initialization
// if the EnclaveConfig specified a port of 0 (indicates that the operating
// system should select an available port).
//
// The server is shut down during Finalize(). To ensure proper server shutdown,
// users of this class are expected to trigger enclave finalization by calling
// EnclaveManager::DestroyEnclave() at some point during lifetime of their
// application.
class EnclaveServer final : public TrustedApplication {
 public:
  using GrpcServiceFactory =
      std::function<StatusOr<std::unique_ptr<::grpc::Service>>()>;

  EnclaveServer(std::unique_ptr<::grpc::Service> service,
                std::shared_ptr<::grpc::ServerCredentials> credentials)
      : server_{nullptr},
        service_{std::move(service)},
        service_factory_{NoFactory},
        credentials_{credentials} {}

  EnclaveServer(GrpcServiceFactory service_factory,
                std::shared_ptr<::grpc::ServerCredentials> credentials)
      : server_{nullptr},
        service_factory_{service_factory},
        credentials_{credentials} {}

  ~EnclaveServer() = default;

  // From TrustedApplication.

  Status Initialize(const EnclaveConfig &config) override {
    const ServerConfig &config_server_proto =
        config.GetExtension(server_input_config);
    if (!config_server_proto.has_host()) {
      return Status(
          absl::StatusCode::kFailedPrecondition,
          "No host was set in server_input_config extension of EnclaveConfig");
    }
    if (!config_server_proto.has_port()) {
      return Status(
          absl::StatusCode::kFailedPrecondition,
          "No port was set in server_input_config extension of EnclaveConfig");
    }
    host_ = config_server_proto.host();
    port_ = config_server_proto.port();

    LOG(INFO) << "gRPC server configured with address: " << host_ << ":"
              << port_;

    return InitializeServer();
  }

  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    GetServerAddress(output);
    return absl::OkStatus();
  }

  Status Finalize(const EnclaveFinal &enclave_final) override {
    FinalizeServer();
    return absl::OkStatus();
  }

 private:
  // Initializes a gRPC server. If the server is already initialized, does
  // nothing.
  Status InitializeServer() {
    // Ensure that the server is only created and initialized once.
    auto server_view(server_.Lock());
    if (*server_view) {
      return absl::OkStatus();
    }

    ASYLO_ASSIGN_OR_RETURN(*server_view, CreateServer());
    return absl::OkStatus();
  }

  // Creates a gRPC server that hosts service_ on host_ and port_ with
  // credentials_.
  StatusOr<std::unique_ptr<::grpc::Server>> CreateServer() {
    int port;
    ::grpc::ServerBuilder builder;
    builder.AddListeningPort(absl::StrCat(host_, ":", port_), credentials_,
                             &port);
    if (service_ == nullptr) {
      StatusOr<std::unique_ptr<::grpc::Service>> service_result =
          service_factory_();
      if (!service_result.ok()) {
        return service_result.status();
      }
      service_ = std::move(service_result).value();
    }
    if (service_ == nullptr) {
      return Status(absl::StatusCode::kInternal, "No gRPC service configured");
    }
    builder.RegisterService(service_.get());
    std::unique_ptr<::grpc::Server> server = builder.BuildAndStart();
    if (!server) {
      return Status(absl::StatusCode::kInternal, "Failed to start gRPC server");
    }

    port_ = port;
    LOG(INFO) << "gRPC server is listening on " << host_ << ":" << port_;

    return std::move(server);
  }

  // Gets the address of the hosted gRPC server and writes it to
  // server_output_config extension of |output|.
  void GetServerAddress(EnclaveOutput *output) {
    ServerConfig *config = output->MutableExtension(server_output_config);
    config->set_host(host_);
    config->set_port(port_);
  }

  // Finalizes the gRPC server by calling ::gprc::Server::Shutdown().
  void FinalizeServer() {
    auto server_view(server_.Lock());
    if (*server_view) {
      LOG(INFO) << "Shutting down...";
      credentials_ = nullptr;
      (*server_view)->Shutdown();
      *server_view = nullptr;
    }
  }

  static StatusOr<std::unique_ptr<::grpc::Service>> NoFactory() {
    return Status(absl::StatusCode::kInternal, "No factory configured");
  }

  // A gRPC server hosting |messenger_|.
  MutexGuarded<std::unique_ptr<::grpc::Server>> server_;

  // The host and port of the server's address.
  std::string host_;
  int port_;

  std::unique_ptr<::grpc::Service> service_;
  GrpcServiceFactory service_factory_;
  std::shared_ptr<::grpc::ServerCredentials> credentials_;
};

}  // namespace asylo

#endif  // ASYLO_GRPC_UTIL_ENCLAVE_SERVER_H_
