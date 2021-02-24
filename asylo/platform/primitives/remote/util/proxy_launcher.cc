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

#include "asylo/platform/primitives/remote/util/proxy_launcher.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/util/logging.h"
#include "asylo/platform/primitives/remote/util/grpc_credential_builder.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

StatusOr<pid_t> LaunchProxy(absl::string_view host_address,
                            absl::string_view remote_proxy) {
  // Prepare remote proxy base name, so that viewers display this proxy
  // process nicely.
  if (remote_proxy.empty()) {
    return absl::FailedPreconditionError("No remote_proxy flag provided");
  }
  std::string proxy_name(remote_proxy.data(), remote_proxy.size());
  std::string process_basename;
  const size_t slash_position = proxy_name.rfind('/');
  if (slash_position == std::string::npos) {
    process_basename = proxy_name;
  } else {
    process_basename = proxy_name.substr(slash_position + 1);
  }

  if (access(proxy_name.c_str(), 0) != 0) {
    return absl::FailedPreconditionError(
        absl::StrCat("Unable to access remote_proxy: ", strerror(errno)));
  }

  // Add security-related flags, if set.
  std::string security_type_param(
      absl::StrCat("--security_type=", absl::GetFlag(FLAGS_security_type)));
  std::string ssl_cert_param;
  std::string ssl_key_param;
  if (!absl::GetFlag(FLAGS_ssl_cert).empty()) {
    ssl_cert_param = absl::StrCat("--ssl_cert=", absl::GetFlag(FLAGS_ssl_cert));
  }
  if (!absl::GetFlag(FLAGS_ssl_key).empty()) {
    ssl_key_param = absl::StrCat("--ssl_key=", absl::GetFlag(FLAGS_ssl_key));
  }

  // Fork remote enclave proxy process that will later load the Enclave.
  std::string host_address_param(absl::StrCat("--host_address=", host_address));
  auto remote_target_pid = fork();
  if (remote_target_pid < 0) {
    return absl::ResourceExhaustedError(
        absl::StrCat("Failed to fork remote proxy process: ", strerror(errno)));
  }
  if (remote_target_pid == 0) {
    execl(proxy_name.c_str(), process_basename.c_str(),
          host_address_param.c_str(), security_type_param.c_str(),
          ssl_cert_param.c_str(), ssl_key_param.c_str(), nullptr);
    LOG(FATAL) << "Failed to execute proxy_test_process: " << strerror(errno);
  }
  return remote_target_pid;
}

void WaitProxyTermination(pid_t remote_target_pid) {
  int wstatus;
  waitpid(remote_target_pid, &wstatus, 0);
  CHECK_EQ(0, wstatus) << strerror(errno);
}

}  // namespace asylo
