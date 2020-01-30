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

#include "asylo/platform/posix/syscall/enclave_syscall_helper.h"

#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/system_call/system_call.h"

namespace asylo {
namespace system_call {

EnclaveSyscallHelper::EnclaveSyscallHelper() = default;

EnclaveSyscallHelper::~EnclaveSyscallHelper() = default;

EnclaveSyscallHelper* EnclaveSyscallHelper::GetInstance() {
  static auto* instance = new EnclaveSyscallHelper;
  return instance;
}

int64_t EnclaveSyscallHelper::DispatchSyscall(int sysno, uint64_t args[],
                                              size_t nargs) {
  switch (nargs) {
    case 0:
      return EnsureInitializedAndDispatchSyscall(sysno);
    case 1:
      return EnsureInitializedAndDispatchSyscall(sysno, args[0]);
    case 2:
      return EnsureInitializedAndDispatchSyscall(sysno, args[0], args[1]);
    case 3:
      return EnsureInitializedAndDispatchSyscall(sysno, args[0], args[1],
                                                 args[2]);
    case 4:
      return EnsureInitializedAndDispatchSyscall(sysno, args[0], args[1],
                                                 args[2], args[3]);
    case 5:
      return EnsureInitializedAndDispatchSyscall(sysno, args[0], args[1],
                                                 args[2], args[3], args[4]);
    case 6:
      return EnsureInitializedAndDispatchSyscall(
          sysno, args[0], args[1], args[2], args[3], args[4], args[5]);
    default:
      return -1;
  }
}

}  // namespace system_call
}  // namespace asylo
