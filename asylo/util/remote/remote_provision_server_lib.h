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

#ifndef ASYLO_UTIL_REMOTE_REMOTE_PROVISION_SERVER_LIB_H_
#define ASYLO_UTIL_REMOTE_REMOTE_PROVISION_SERVER_LIB_H_

#include "absl/container/flat_hash_set.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/remote/remote_provision.grpc.pb.h"
#include "asylo/util/remote/remote_provision.pb.h"
#include "asylo/util/statusor.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/impl/codegen/sync_stream.h"
#include "include/grpcpp/support/status.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server_builder.h"

namespace asylo {

class ProvisionServiceImpl : public ProvisionService::Service {
 public:
  explicit ProvisionServiceImpl(absl::string_view storage_dir)
      : storage_dir_(storage_dir),
        remote_targets_pids_(absl::flat_hash_set<pid_t>()) {}
  ProvisionServiceImpl(const ProvisionServiceImpl &other) = delete;
  ProvisionServiceImpl &operator=(const ProvisionServiceImpl &other) = delete;

  grpc::Status Provision(grpc::ServerContext *context,
                         grpc::ServerReader<ProvisionRequest> *reader,
                         ProvisionResponse *response) override;

 private:
  StatusOr<std::string> PrepareEnclave(
      grpc::ServerReader<ProvisionRequest> *reader);

  std::atomic<uint64_t> enclave_index_{0};
  const std::string storage_dir_;
  MutexGuarded<absl::flat_hash_set<pid_t>> remote_targets_pids_;
};

class RemoteProvisionServer {
 public:
  static StatusOr<std::unique_ptr<RemoteProvisionServer>> Create(
      ::grpc::ServerBuilder *builder, absl::string_view temporary_directory);

  ~RemoteProvisionServer() = default;

  explicit RemoteProvisionServer(absl::string_view temporary_directory)
      : provision_service_(temporary_directory) {}
  RemoteProvisionServer(const RemoteProvisionServer &other) = delete;
  RemoteProvisionServer &operator=(const RemoteProvisionServer &other) = delete;

 private:
  ProvisionServiceImpl provision_service_;
};

}  //  namespace asylo

#endif  // ASYLO_UTIL_REMOTE_REMOTE_PROVISION_SERVER_LIB_H_
