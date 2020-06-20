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

#include <cstdint>
#include <string>

#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/platform/primitives/remote/util/proxy_launcher.h"
#include "asylo/util/remote/provision.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

ABSL_FLAG(std::string, remote_proxy, "",
          "Path to binary for running RemoteEnclaveProxyServer");

namespace asylo {
namespace {

class LocalRemoteProxyProvision : public RemoteProvision {
 public:
  LocalRemoteProxyProvision() = default;
  LocalRemoteProxyProvision(const LocalRemoteProxyProvision &other) = delete;
  LocalRemoteProxyProvision &operator=(const LocalRemoteProxyProvision &other) =
      delete;

  ~LocalRemoteProxyProvision() override { Finalize(); }

  StatusOr<std::string> Provision(int32_t client_port,
                                  absl::string_view enclave_path) override {
    ASYLO_ASSIGN_OR_RETURN(remote_target_pid_,
                           LaunchProxy(absl::StrCat("[::]:", client_port),
                                       absl::GetFlag(FLAGS_remote_proxy)));
    // Enclave location does not change.
    return std::string(enclave_path);
  }

  void Finalize() override {
    // It is safe to call Finalize more than once: the first call would set
    // pid to 0, and the ensuing calls will be a no-op.
    // Finalize is expected to be called when the remote client shuts down, but
    // if something goes wrong, it will be still called by destructor, thus
    // making sure that forked process is terminated before its parent.
    if (remote_target_pid_ != 0) {
      WaitProxyTermination(remote_target_pid_);
      remote_target_pid_ = 0;
    }
  }

 private:
  pid_t remote_target_pid_ = 0;
};

}  // namespace

std::unique_ptr<RemoteProvision> RemoteProvision::Instantiate() {
  return absl::make_unique<LocalRemoteProxyProvision>();
}

}  // namespace asylo
