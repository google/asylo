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

#ifndef ASYLO_PLATFORM_SYSTEM_CALL_UNTRUSTED_INVOKE_H_
#define ASYLO_PLATFORM_SYSTEM_CALL_UNTRUSTED_INVOKE_H_

#include <vector>

#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"

namespace asylo {
namespace system_call {

// Invokes the native Linux system call described by `request` and builds the
// response message in `response`. Return true on success, otherwise false if a
// serialization error occurred.
primitives::PrimitiveStatus UntrustedInvoke(primitives::Extent request,
                                            primitives::Extent *response);

}  // namespace system_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_SYSTEM_CALL_UNTRUSTED_INVOKE_H_
