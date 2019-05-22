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

#include <stddef.h>
#include <stdint.h>

#include "asylo/platform/system_call/message.h"

namespace asylo {
namespace system_call {
namespace {

// Tests passing a random byte buffer into MessageReader, and verifies it does
// not point to data outside the input buffer in the fuzzer environment, see
// http://llvm.org/docs/LibFuzzer.html.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  MessageReader reader({data, size});
  if (reader.Validate().ok()) {
    FormatMessage(primitives::Extent(data, size));
  }

  return 0;
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
