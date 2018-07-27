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

#include <chrono>
#include <memory>

#include "absl/synchronization/mutex.h"
#include "asylo/examples/grpc_server/grpc_server_config.pb.h"
#include "asylo/examples/grpc_server/translator_server.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server.h"
#include "include/grpcpp/server_builder.h"

namespace examples {
namespace grpc_server {

// An enclave that runs a TranslatorServer. We override the methods of
// TrustedApplication as follows:
//
// * Initialize starts the gRPC server.
// * Run does nothing. See the exercises section of the README.md for some
//   possible uses of this method.
// * Finalize shuts down the gRPC server.
class GrpcServerEnclave final : public asylo::TrustedApplication {
 public:
  GrpcServerEnclave() = default;

  asylo::Status Initialize(const asylo::EnclaveConfig &enclave_config)
      LOCKS_EXCLUDED(server_mutex_) override;

  asylo::Status Run(const asylo::EnclaveInput &enclave_input,
                    asylo::EnclaveOutput *enclave_output) override {
    return asylo::Status::OkStatus();
  }

  asylo::Status Finalize(const asylo::EnclaveFinal &enclave_final)
      LOCKS_EXCLUDED(server_mutex_) override;

 private:
  // Guards the |server_| member.
  absl::Mutex server_mutex_;

  // A gRPC server hosting |service_|.
  std::unique_ptr<::grpc::Server> server_ GUARDED_BY(server_mutex_);

  // The translation service.
  TranslatorServer service_;
};

asylo::Status GrpcServerEnclave::Initialize(
    const asylo::EnclaveConfig &enclave_config) LOCKS_EXCLUDED(server_mutex_) {
  // Fail if there is no server_address available.
  if (!enclave_config.HasExtension(server_address)) {
    return asylo::Status(asylo::error::GoogleError::INVALID_ARGUMENT,
                         "Expected a server_address extension on config.");
  }

  // Lock |server_mutex_| so that we can start setting up the server.
  absl::MutexLock lock(&server_mutex_);

  // Check that the server is not already running.
  if (server_) {
    return asylo::Status(asylo::error::GoogleError::ALREADY_EXISTS,
                         "Server is already started");
  }

  // Create a ServerBuilder object to set up the server.
  ::grpc::ServerBuilder builder;

  // Add a listening port to the server.
  //
  // Note: This gRPC server is hosted with InsecureServerCredentials. This
  // means that no additional security is used for channel establishment.
  // Neither the server nor its clients are authenticated, and no channels are
  // secured. This configuration is not suitable for a production environment.
  int selected_port;
  builder.AddListeningPort(enclave_config.GetExtension(server_address),
                           ::grpc::InsecureServerCredentials(), &selected_port);

  // Add the translator service to the server.
  builder.RegisterService(&service_);

  // Start the server.
  server_ = builder.BuildAndStart();
  if (!server_) {
    return asylo::Status(asylo::error::GoogleError::INTERNAL,
                         "Failed to start server");
  }

  LOG(INFO) << "Server started on port " << selected_port;

  return asylo::Status::OkStatus();
}

asylo::Status GrpcServerEnclave::Finalize(
    const asylo::EnclaveFinal &enclave_final) LOCKS_EXCLUDED(server_mutex_) {
  // Lock |server_mutex_| so that we can start shutting down the server.
  absl::MutexLock lock(&server_mutex_);

  // If the server exists, then shut it down. Also delete the Server object to
  // indicate that it is no longer valid.
  if (server_) {
    LOG(INFO) << "Server shutting down";

    // Give all outstanding RPC calls 500 milliseconds to complete.
    server_->Shutdown(std::chrono::system_clock::now() +
                      std::chrono::milliseconds(500));
    server_.reset(nullptr);
  }

  return asylo::Status::OkStatus();
}

}  // namespace grpc_server
}  // namespace examples

namespace asylo {

TrustedApplication *BuildTrustedApplication() {
  return new examples::grpc_server::GrpcServerEnclave;
}

}  // namespace asylo
