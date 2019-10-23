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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_UTIL_PROXY_LAUNCHER_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_UTIL_PROXY_LAUNCHER_H_

#include <sys/types.h>

#include "absl/strings/string_view.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Helper function launches a remote proxy process with given path.
// Sets host_address parameter.
// Returns pid of the child process or status in case of any error.
StatusOr<pid_t> LaunchProxy(absl::string_view host_address,
                            absl::string_view remote_proxy);

// Helper function waits for the remote proxt process to terminate.
void WaitProxyTermination(pid_t remote_target_pid);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_UTIL_PROXY_LAUNCHER_H_
