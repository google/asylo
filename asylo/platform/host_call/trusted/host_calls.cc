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

#include "asylo/platform/host_call/trusted/host_calls.h"

#include <errno.h>

#include "asylo/platform/host_call/exit_handler_constants.h"
#include "asylo/platform/host_call/trusted/host_call_dispatcher.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"

extern "C" {

void init_host_calls() {
  enc_set_dispatch_syscall(asylo::host_call::SystemCallDispatcher);
}

int enc_untrusted_access(const char *path_name, int mode) {
  return enc_untrusted_syscall(asylo::system_call::kSYS_access, path_name,
                               mode);
}

pid_t enc_untrusted_getpid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_getpid);
}

pid_t enc_untrusted_getppid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_getppid);
}

pid_t enc_untrusted_setsid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_setsid);
}

uid_t enc_untrusted_getuid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_getuid);
}

gid_t enc_untrusted_getgid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_getgid);
}

uid_t enc_untrusted_geteuid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_geteuid);
}

gid_t enc_untrusted_getegid() {
  return enc_untrusted_syscall(asylo::system_call::kSYS_getegid);
}

}  // extern "C"
