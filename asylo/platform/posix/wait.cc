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

#include <sys/wait.h>

#include "asylo/platform/host_call/trusted/host_calls.h"

extern "C" {

int enclave_wait(int *wstatus) { return enc_untrusted_wait(wstatus); }

pid_t wait3(int *wstatus, int options, struct rusage *usage) {
  return enc_untrusted_wait3(wstatus, options, usage);
}

pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *usage) {
  return enc_untrusted_wait4(pid, wstatus, options, usage);
}

pid_t waitpid(pid_t pid, int *wstatus, int options) {
  return enc_untrusted_waitpid(pid, wstatus, options);
}

}  // extern "C"
