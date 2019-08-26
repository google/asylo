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

#include "asylo/platform/primitives/test/remote_test_backend.h"

#include <sys/wait.h>

#include <memory>
#include <string>

#include "absl/flags/flag.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/remote/proxy_client.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/util/path.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/security/credentials.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/support/channel_arguments.h"

ABSL_FLAG(std::string, proxy_binary, "",
          "Path to the binary running EnclaveProxyServer");

ABSL_FLAG(std::string, enclave_binary, "",
          "Path to the Sim enclave binary to be loaded remotely");

namespace asylo {
namespace primitives {
namespace test {

RemoteTestBackend::~RemoteTestBackend() {
  if (remote_target_pid_ != 0) {
    FinalizeTestEnclave();
  }
}

void RemoteTestBackend::FinalizeTestEnclave() {
  int wstatus;
  waitpid(remote_target_pid_, &wstatus, 0);
  CHECK_EQ(0, wstatus) << strerror(errno);
  remote_target_pid_ = 0;
}

StatusOr<std::shared_ptr<Client>> RemoteTestBackend::LoadTestEnclave(
    const absl::string_view enclave_name,
    std::unique_ptr<Client::ExitCallProvider> exit_call_provider) {
  const std::string kRunfilesWorkspace =
      asylo::JoinPath(getenv("TEST_SRCDIR"), "com_google_asylo");
  const std::string proxy_binary =
      asylo::JoinPath(kRunfilesWorkspace, absl::GetFlag(FLAGS_proxy_binary));
  const std::string enclave_binary =
      asylo::JoinPath(kRunfilesWorkspace, absl::GetFlag(FLAGS_enclave_binary));

  std::shared_ptr<RemoteEnclaveProxyClient> client;
  ASYLO_ASSIGN_OR_RETURN(
      client,
      RemoteEnclaveProxyClient::Create(
          enclave_name, ::grpc::InsecureChannelCredentials(),
          ::grpc::ChannelArguments(), ::grpc::InsecureServerCredentials(),
          std::move(exit_call_provider), [this] { FinalizeTestEnclave(); }));

  // Start test enclave process to load the simulated Enclave.
  // This action is test-specific; in production and in other tests the
  // process would be assigned by a provisioning layer.
  std::string process_basename;
  const size_t slash_position = proxy_binary.rfind("/");
  if (slash_position == std::string::npos) {
    process_basename = proxy_binary;
  } else {
    process_basename = proxy_binary.substr(slash_position + 1);
  }
  std::string host_address_param(absl::StrCat(
      "--host_address=[::]:", client->communicator()->server_port()));
  remote_target_pid_ = fork();
  if (remote_target_pid_ == 0) {
    execl(proxy_binary.c_str(), process_basename.c_str(),
          host_address_param.c_str(), nullptr);
    LOG(FATAL) << "Failed to execute proxy_test_process: " << strerror(errno);
  }

  // This message would normally be created by the RemoteEnclaveLoader by
  // calling the loader_->SerializeLoader().
  MessageWriter load_in;
  load_in.Push(enclave_binary);

  // Connect the client to the remote Enclave server running remotely.
  ASYLO_RETURN_IF_ERROR(client->Connect(&load_in));

  // Client is ready, return it.
  return client;
}

TestBackend *TestBackend::Get() {
  static TestBackend *backend = new RemoteTestBackend;
  return backend;
}

}  // namespace test
}  // namespace primitives
}  // namespace asylo
