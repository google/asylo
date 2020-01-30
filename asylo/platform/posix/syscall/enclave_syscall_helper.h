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

#ifndef ASYLO_PLATFORM_POSIX_SYSCALL_ENCLAVE_SYSCALL_HELPER_H_
#define ASYLO_PLATFORM_POSIX_SYSCALL_ENCLAVE_SYSCALL_HELPER_H_

#include <cstdint>
#include <cstdlib>

namespace asylo {
namespace system_call {

class EnclaveSyscallHelper {
 public:
  EnclaveSyscallHelper();
  virtual ~EnclaveSyscallHelper();

  // EnclaveSyscallHelper is neither copyable nor movable.
  EnclaveSyscallHelper(const EnclaveSyscallHelper&) = delete;
  EnclaveSyscallHelper& operator=(const EnclaveSyscallHelper&) = delete;

  // Access to the singleton instance.
  static EnclaveSyscallHelper* GetInstance();

  // Makes the syscall against enc_untrusted_syscall in the system call library.
  virtual int64_t DispatchSyscall(int sysno, uint64_t args[], size_t nargs);
};

}  // namespace system_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_SYSCALL_ENCLAVE_SYSCALL_HELPER_H_
