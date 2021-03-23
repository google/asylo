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

#include <fcntl.h>

#include <cstdint>
#include <string>

#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/platform/primitives/remote/util/grpc_credential_builder.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/remote/grpc_channel_builder.h"
#include "asylo/util/remote/provision.h"
#include "asylo/util/remote/remote_provision.grpc.pb.h"
#include "asylo/util/remote/remote_provision.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/impl/codegen/sync_stream.h"
#include "include/grpcpp/support/status.h"
#include "include/grpcpp/channel.h"
#include "include/grpcpp/create_channel.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/support/channel_arguments.h"

ABSL_FLAG(std::string, remote_provision_server, "",
          "Network address of remote provisioning server (IP:port)");

ABSL_FLAG(std::string, local_client_name, "",
          "Network name of local client (IP)");

namespace asylo {
namespace {

class RemoteProvisionClient : public RemoteProvision {
 public:
  RemoteProvisionClient() = default;

  RemoteProvisionClient(const RemoteProvisionClient &other) = delete;
  RemoteProvisionClient &operator=(const RemoteProvisionClient &other) = delete;

  ~RemoteProvisionClient() override { Finalize(); }

  StatusOr<std::string> Provision(int32_t client_port,
                                  absl::string_view enclave_path) override {
    // Connect to the remote provision server.
    const auto provision_server = absl::GetFlag(FLAGS_remote_provision_server);
    if (provision_server.empty()) {
      return absl::FailedPreconditionError(
          "No remote provision server specified.");
    }
    std::shared_ptr<::grpc::Channel> grpc_channel;
    ASYLO_ASSIGN_OR_RETURN(grpc_channel,
                           GrpcChannelBuilder::BuildChannel(provision_server));
    gpr_timespec absolute_deadline = gpr_time_add(
        gpr_now(GPR_CLOCK_REALTIME), gpr_time_from_seconds(10, GPR_TIMESPAN));
    if (!grpc_channel->WaitForConnected(absolute_deadline)) {
      return absl::DeadlineExceededError("Failed to connect");
    }
    std::unique_ptr<ProvisionService::Stub> grpc_stub =
        ProvisionService::NewStub(grpc_channel);

    // Request the remote provision server to launch an enclave proxy process
    // to load the Enclave.
    return SendEnclave(
        enclave_path,
        absl::StrCat(absl::GetFlag(FLAGS_local_client_name), ":", client_port),
        grpc_stub.get());
  }

  void Finalize() override {}

 private:
  StatusOr<std::string> SendEnclave(
      absl::string_view enclave_file_path, absl::string_view client_address,
      ProvisionService::Stub *grpc_stub) {
    LOG(INFO) << "Read file: " << enclave_file_path;
    int fd = open(std::string(enclave_file_path).c_str(), O_RDONLY);
    if (fd < 0) {
      return LastPosixError(
          absl::StrCat("Failed to open file ", enclave_file_path));
    }
    Cleanup closer([fd] { close(fd); });

    ::grpc::ClientContext context;
    ProvisionResponse response;
    auto stream = grpc_stub->Provision(&context, &response);
    {
      Cleanup done([&stream] {
        if (!stream->WritesDone()) {
          LOG(ERROR) << "WritesDone failed";
        }
      });
      ProvisionRequest request;
      request.set_client_address(client_address.data(), client_address.size());

      // One megabyte determined to be good buffer length.
      static constexpr int kBufferLength = 1024 * 1024;
      request.mutable_enclave_binary()->resize(kBufferLength);
      auto read_buf =
          const_cast<char *>(request.mutable_enclave_binary()->data());

      Sha256Hash hasher;
      std::vector<uint8_t> cumulative_hash;

      // Read enclave binary block by block, calculate cumulative SHA256 and
      // send.
      while (true) {
        ssize_t len = read(fd, read_buf, kBufferLength);
        if (len == 0) {
          break;
        } else if (len < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            continue;
          } else {
            return LastPosixError(
                absl::StrCat("Failed to read file ", enclave_file_path));
          }
        }

        hasher.Update(ByteContainerView(read_buf, len));
        ASYLO_RETURN_IF_ERROR(hasher.CumulativeHash(&cumulative_hash));
        request.set_cumulative_sha256(
            std::string(cumulative_hash.begin(), cumulative_hash.end()));
        request.mutable_enclave_binary()->resize(len);
        if (!stream->Write(request)) {
          LOG(ERROR) << "Write failed";
          break;
        }
        // No client address after the first block.
        request.clear_client_address();
      }
    }

    ASYLO_RETURN_IF_ERROR(ConvertStatus<asylo::Status>(stream->Finish()));
    if (response.enclave_path().empty()) {
      return absl::NotFoundError("No enclave file path");
    }
    LOG(INFO) << "Enclave sent successfully, path=" << response.enclave_path();
    return response.enclave_path();
  }
};

}  // namespace

std::unique_ptr<RemoteProvision> RemoteProvision::Instantiate() {
  return absl::make_unique<RemoteProvisionClient>();
}

}  // namespace asylo
