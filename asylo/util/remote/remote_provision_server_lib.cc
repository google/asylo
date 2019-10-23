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

#include "asylo/util/remote/remote_provision_server_lib.h"

#include <fcntl.h>
#include <openssl/sha.h>

#include <cstdint>
#include <memory>
#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/platform/primitives/remote/util/proxy_launcher.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/path.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/remote/grpc_server_main_wrapper.h"
#include "asylo/util/remote/process_main_wrapper.h"
#include "asylo/util/remote/remote_provision.grpc.pb.h"
#include "asylo/util/remote/remote_provision.pb.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/thread.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/impl/codegen/sync_stream.h"
#include "include/grpcpp/support/status.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server_builder.h"


ABSL_FLAG(std::string, remote_proxy, "",
          "Path to binary for running RemoteEnclaveProxyServer");

namespace asylo {

grpc::Status ProvisionServiceImpl::Provision(
    grpc::ServerContext *context,
    grpc::ServerReader<ProvisionRequest> *reader,
    ProvisionResponse *response) {
  auto filename_or_status = PrepareEnclave(reader);
  if (!filename_or_status.ok()) {
    return filename_or_status.status().ToOtherStatus<grpc::Status>();
  }
  // Return location of the enclave in the file system, accessible by the
  // proxy.
  response->set_enclave_path(filename_or_status.ValueOrDie());
  return grpc::Status::OK;
}

StatusOr<std::string> ProvisionServiceImpl::PrepareEnclave(
    grpc::ServerReader<ProvisionRequest> *reader) {
  const std::string filename =
      JoinPath(storage_dir_, absl::StrCat("enclave_", ++enclave_index_));
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  {
    ProvisionRequest request;
    if (!reader->Read(&request)) {
      return Status{error::GoogleError::INVALID_ARGUMENT,
                    "Could not read the request."};
    }

    if (request.client_address().empty()) {
      return Status{error::GoogleError::INVALID_ARGUMENT,
                    "Client_address absent"};
    }
    pid_t remote_target_pid;
    ASYLO_ASSIGN_OR_RETURN(remote_target_pid,
                           LaunchProxy(request.client_address(),
                                       absl::GetFlag(FLAGS_remote_proxy)));
    request.clear_client_address();
    remote_targets_pids_.Lock()->emplace(remote_target_pid);

    // Create a thread to wait for the forked process to finish.
    Thread::StartDetached([remote_target_pid, this] {
      WaitProxyTermination(remote_target_pid);
      remote_targets_pids_.Lock()->erase(remote_target_pid);
    });

    // Read and store the enclave binary.
    int fd = open(filename.c_str(), O_CREAT | O_WRONLY,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
      return Status{static_cast<error::PosixError>(errno),
                    absl::StrCat("Failed to open file ", filename)};
    }
    Cleanup closer([fd] { close(fd); });

    do {
      if (!request.enclave_binary().empty()) {
        SHA256_Update(&sha256, request.enclave_binary().data(),
                      request.enclave_binary().size());
        std::string hash(SHA256_DIGEST_LENGTH, '\0');
        SHA256_Final(
            reinterpret_cast<uint8_t *>(const_cast<char *>(hash.data())),
            &sha256);
        if (request.cumulative_sha256() != hash) {
          return Status{error::GoogleError::DATA_LOSS,
                        "SHA256 hash mismatch"};
        }
        int write_res = write(fd, request.enclave_binary().data(),
                              request.enclave_binary().size());
        if (write_res < request.enclave_binary().size()) {
          return Status{static_cast<error::PosixError>(errno),
                        absl::StrCat("Failed to write into file ", filename)};
        }
      }
      if (!request.client_address().empty()) {
        return Status{
            error::GoogleError::FAILED_PRECONDITION,
            "Client address present in more than on streamed request"};
      }
    } while (reader->Read(&request));
  }

  // Return location of the enclave in the file system, accessible by the
  // proxy.
  LOG(INFO) << "Enclave successfully uploaded, filename=" << filename;
  return filename;
}

StatusOr<std::unique_ptr<RemoteProvisionServer>> RemoteProvisionServer::Create(
      ::grpc::ServerBuilder *builder, absl::string_view temporary_directory) {
  // Check flags.
  if (absl::GetFlag(FLAGS_remote_proxy).empty()) {
    return Status{error::GoogleError::FAILED_PRECONDITION,
                  "No --remote_proxy flag specified"};
  }
  // Create provision server.
  auto server = absl::make_unique<RemoteProvisionServer>(temporary_directory);
  // Register services.
  builder->RegisterService(&server->provision_service_);
  return std::move(server);
}

}  // namespace asylo

