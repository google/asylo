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

#ifndef ASYLO_PLATFORM_SYSTEM_CALL_SERIALIZE_H_
#define ASYLO_PLATFORM_SYSTEM_CALL_SERIALIZE_H_

#include <array>
#include <cstdint>

#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/system_call/message.h"

namespace asylo {
namespace system_call {

// An array of parameters to a Linux system call.
using ParameterList = std::array<uint64_t, kParameterMax>;

// Serializes a system call request specified by a system call number and a list
// of parameters into a buffer. On success, `request` is populated with a buffer
// allocated by malloc and owned by the caller.
primitives::PrimitiveStatus SerializeRequest(int sysno,
                                             const ParameterList &parameters,
                                             primitives::Extent *request);

// Serializes a system call response specified by a system call number, a return
// code, and a list of parameters into a buffer. On success, `response` is
// populated with a buffer allocated by malloc and owned by the caller.
primitives::PrimitiveStatus SerializeResponse(int sysno, uint64_t result,
                                              uint64_t error_number,
                                              const ParameterList &parameters,
                                              primitives::Extent *response);

}  // namespace system_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_SERIALIZE_H_
