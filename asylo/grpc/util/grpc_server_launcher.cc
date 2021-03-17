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

#include "asylo/grpc/util/grpc_server_launcher.h"

#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "asylo/util/logging.h"

namespace asylo {

Status GrpcServerLauncher::RegisterService(
    std::unique_ptr<::grpc::Service> service) {
  absl::MutexLock lock(&mu_);
  if (state_ != State::NOT_LAUNCHED) {
    return MakeStatus(absl::StatusCode::kFailedPrecondition,
                      "Cannot add services after the server has started");
  }
  builder_.RegisterService(service.get());
  services_.emplace_back(std::move(service));
  return absl::OkStatus();
}

Status GrpcServerLauncher::AddListeningPort(
    const std::string &address,
    std::shared_ptr<::grpc::ServerCredentials> creds, int *selected_port) {
  absl::MutexLock lock(&mu_);
  if (state_ != State::NOT_LAUNCHED) {
    return MakeStatus(
        absl::StatusCode::kFailedPrecondition,
        "Cannot add address and creds after the server has started");
  }
  builder_.AddListeningPort(address, std::move(creds), selected_port);
  LOG(INFO) << "Added listening port \"" << address << "\" to the server";
  return absl::OkStatus();
}

Status GrpcServerLauncher::Start() {
  absl::MutexLock lock(&mu_);
  if (state_ != State::NOT_LAUNCHED) {
    return MakeStatus(absl::StatusCode::kFailedPrecondition,
                      "Cannot start server more than once");
  }
  server_ = builder_.BuildAndStart();
  if (!server_) {
    state_ = State::TERMINATED;
    return MakeStatus(absl::StatusCode::kInternal,
                      "Failed to start the server ");
  }
  state_ = State::LAUNCHED;
  return absl::OkStatus();
}

Status GrpcServerLauncher::Shutdown() {
  absl::MutexLock lock(&mu_);
  if (state_ != State::LAUNCHED) {
    // Prevent further attempts to launch the server once Shutdown() has been
    // called.
    state_ = State::TERMINATED;
    return MakeStatus(absl::StatusCode::kFailedPrecondition,
                      "Cannot shutdown, the server has not started");
  }

  server_->Shutdown();
  state_ = State::TERMINATED;

  return absl::OkStatus();
}

Status GrpcServerLauncher::Wait() const {
  {
    // Grab the mutex mu_ only while checking the current state, but release it
    // before calling server_->Wait(). Keeping mu_ locked while calling
    // server_->Wait() makes it impossible to shut down the server.
    absl::MutexLock lock(&mu_);
    if (state_ != State::LAUNCHED) {
      return MakeStatus(absl::StatusCode::kFailedPrecondition,
                        "Cannot wait, the server is not running");
    }
  }

  // The ::grpc::Server object itself is thread-safe, and as a result, it is OK
  // to call the Wait() method on this object without grabbing |mu_|.
  server_->Wait();
  return absl::OkStatus();
}

GrpcServerLauncher::State GrpcServerLauncher::GetState() {
  absl::MutexLock lock(&mu_);
  // Reading the member variable state_ from inside a critical section ensures
  // that the object has reached a consistent state.
  return state_;
}

}  // namespace asylo
