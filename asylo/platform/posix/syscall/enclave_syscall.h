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

#ifndef ASYLO_PLATFORM_POSIX_SYSCALL_ENCLAVE_SYSCALL_H_
#define ASYLO_PLATFORM_POSIX_SYSCALL_ENCLAVE_SYSCALL_H_

#include <sys/inotify.h>

#include <cstdint>
#include <cstdlib>

#include "asylo/platform/posix/io/io_manager.h"
#include "asylo/platform/posix/syscall/enclave_syscall_helper.h"
#include "asylo/platform/system_call/sysno.h"

namespace asylo {
namespace system_call {

// This helper function implements the functionality of enclave_syscall. We
// expose it in this header so that the unit test can call it directly and
// mock its dependencies.
int64_t EnclaveSyscallWithDeps(int sysno, uint64_t *args, size_t nargs,
                               asylo::system_call::EnclaveSyscallHelper *helper,
                               asylo::io::IOManager *io_manager);

}  // namespace system_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_SYSCALL_ENCLAVE_SYSCALL_H_
