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

#ifndef ASYLO_PLATFORM_HOST_CALL_UNTRUSTED_HOST_CALL_HANDLERS_UTIL_H_
#define ASYLO_PLATFORM_HOST_CALL_UNTRUSTED_HOST_CALL_HANDLERS_UTIL_H_

#include "asylo/platform/primitives/util/message.h"
#include "asylo/util/status.h"

namespace asylo {
namespace host_call {

Status SysFutexWaitHelper(primitives::MessageReader *input,
                          primitives::MessageWriter *output);
Status SysFutexWakeHelper(primitives::MessageReader *input,
                          primitives::MessageWriter *output);

}  // namespace host_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_HOST_CALL_UNTRUSTED_HOST_CALL_HANDLERS_UTIL_H_
