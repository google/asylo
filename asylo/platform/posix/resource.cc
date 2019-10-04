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

#include <sys/resource.h>

#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/posix/io/io_manager.h"

extern "C" {

int getrlimit(int resource, struct rlimit *rlim) {
  switch (resource) {
    case RLIMIT_NOFILE:
      return asylo::io::IOManager::GetInstance().GetRLimit(resource, rlim);
    default:
      errno = ENOSYS;
      return -1;
  }
}

int setrlimit(int resource, const struct rlimit *rlim) {
  switch (resource) {
    case RLIMIT_NOFILE:
      return asylo::io::IOManager::GetInstance().SetRLimit(resource, rlim);
    default:
      errno = ENOSYS;
      return -1;
  }
}

int getrusage(int who, struct rusage *usage) {
  return enc_untrusted_getrusage(who, usage);
}

}  // extern "C"
