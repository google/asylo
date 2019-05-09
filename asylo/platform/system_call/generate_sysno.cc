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

#include <iostream>

#include "absl/strings/str_format.h"
#include "asylo/platform/system_call/metadata.h"

constexpr char kPrologue[] = R"(
// Generated file. See "generate_sysno.cc".

#ifndef THIRD_PARTY_ASYLO_PLATFORM_SYSTEM_CALL_SYSNO_H_
#define THIRD_PARTY_ASYLO_PLATFORM_SYSTEM_CALL_SYSNO_H_

namespace asylo {
namespace system_call {

)";

constexpr char kEpilogue[] = R"(
}  // namespace asylo
}  // namespace system_call

#endif  // THIRD_PARTY_ASYLO_PLATFORM_SYSTEM_CALL_SYSNO_H_
)";

// Code generation utility that emits an include file of Linux system call ABI
// numbers. For example:
//
// ```c++
// constexpr int kSYS_fstat = 5;
// ```
int main(int argc, char **argv) {
  std::cout << kPrologue;
  for (int i = 0; i <= asylo::system_call::LastSystemCall(); i++) {
    asylo::system_call::SystemCallDescriptor syscall(i);
    if (syscall.is_valid()) {
      std::cout << absl::StreamFormat("  constexpr int kSYS_%s = %i;\n",
                                      syscall.name(), i);
    }
  }
  std::cout << kEpilogue;
  return 0;
}
