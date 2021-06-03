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

#include "asylo/platform/primitives/remote/util/remote_proxy_lib.h"

#include <string>
#include <utility>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "asylo/enclave.pb.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/dlopen/untrusted_dlopen.h"
#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/remote/communicator.h"
#include "asylo/platform/primitives/remote/proxy_server.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/remote/process_main_wrapper.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

ABSL_FLAG(std::string, host_address, "[::]:8888",
          "Address that remote enclave calls back to the host");

using ::asylo::EnclaveLoadConfig;
using ::asylo::ProcessMainWrapper;
using ::asylo::RemoteProxyServerConfig;
using ::asylo::StatusOr;
using ::asylo::primitives::Client;
using ::asylo::primitives::LocalEnclaveFactory;
using ::asylo::primitives::MessageWriter;
using ::asylo::primitives::RemoteEnclaveProxyServer;

StatusOr<EnclaveLoadConfig> LocalEnclaveFactory::ParseEnclaveLoadConfig(
    MessageWriter *enclave_params) {
  constexpr uint64_t kExpectedNumArgs = 1;
  if (enclave_params->size() != kExpectedNumArgs) {
    return Status{
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Expected ", kExpectedNumArgs, " parameters, received ",
                     enclave_params->size())};
  }
  const size_t size = enclave_params->MessageSize();
  const auto buffer = absl::make_unique<char[]>(size);
  enclave_params->Serialize(buffer.get());

  MessageReader load_params;
  load_params.Deserialize(buffer.get(), size);

  const auto param = load_params.next();

  EnclaveLoadConfig load_config;
  if (!load_config.ParseFromArray(param.data(), param.size())) {
    return Status(absl::StatusCode::kInternal,
                  "Unable to parse EnclaveLoadConfig from param");
  }
  return load_config;
}

int main(int argc, char **argv) {
  absl::ParseCommandLine(argc, argv);

  auto config_or_request = RemoteProxyServerConfig::DefaultsWithHostAddress(
      absl::GetFlag(FLAGS_host_address));
  if (!config_or_request.ok()) {
    LOG(ERROR) << config_or_request.status();
    return -1;
  }

  const auto run_status =
      ProcessMainWrapper<RemoteEnclaveProxyServer>::RunUntilTerminated(
          std::move(config_or_request.value()),
          [](MessageWriter *enclave_params,
             std::unique_ptr<Client::ExitCallProvider> exit_call_provider) {
            return LocalEnclaveFactory::Get(enclave_params,
                                            std::move(exit_call_provider));
          });
  if (!run_status.ok()) {
    LOG(ERROR) << "Failed to run enclave, status=" << run_status;
    return -1;
  }

  return 0;
}
