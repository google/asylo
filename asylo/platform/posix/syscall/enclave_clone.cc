/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/platform/posix/syscall/enclave_clone.h"

#include <sched.h>

#include "asylo/platform/posix/threading/thread_manager.h"

extern "C" {

int enclave_clone(int (*fn)(void *), void *stack, int flags, void *arg,
                  pid_t *parent_tid, void *tls, pid_t *child_tid) {
  if ((flags | CLONE_THREAD) && (flags | CLONE_SETTLS)) {
    pid_t tid;
    int ret = asylo::ThreadManager::GetInstance()->CreateThread(
        std::bind(fn, arg), &tid, tls);
    *parent_tid = tid;
    return ret;
  }
  errno = ENOSYS;
  return -1;
}

}  // extern "C"
