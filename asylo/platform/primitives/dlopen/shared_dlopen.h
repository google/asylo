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

#ifndef ASYLO_PLATFORM_PRIMITIVES_DLOPEN_SHARED_DLOPEN_H_
#define ASYLO_PLATFORM_PRIMITIVES_DLOPEN_SHARED_DLOPEN_H_

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "asylo/platform/primitives/primitive_status.h"

namespace asylo {
namespace primitives {

// Support for calls from trusted code to untrusted.
constexpr uint64_t dlopen_trampoline_address = 0x7e0000000000;

// Trampoline magic number and version.
constexpr uint64_t kTrampolineMagicNumber =
    0x446c4f54724d6167;  // "DlOTrMag"
constexpr uint64_t kTrampolineVersion = 0;

// Collection of handlers implemented by untrusted dlopen component and passed
// to the trusted one to use. The trusted component is statically built shared
// library, so it cannot just link to them; leaving them unresolved does not
// allow specifying the trusted shared library as 'fully_static_link' and
// mandates setting linkopts = "-rdynamic" when building the untrusted driver
// application. Instead of all this, it is now allocated at a predefined address
// and accessed by casting that address to DlopenTrampoline, allowing to specify
// 'fully_static_link' for the trusted library and eliminating the need in
// "-rdynamic" flag for the untrusted one.
struct DlopenTrampoline {
  uint64_t magic_number;
  uint64_t version;
  PrimitiveStatus (*asylo_exit_call)(uint64_t untrusted_selector,
                                     const void *input, size_t input_size,
                                     void **output, size_t *output_size);
  void *(*asylo_local_alloc_handler)(size_t size);
  void (*asylo_local_free_handler)(void *ptr);
};

// Global accessor to DlopenTrampoline (can be used by both trusted and
// untrusted components).
inline DlopenTrampoline *GetDlopenTrampoline() {
  return reinterpret_cast<DlopenTrampoline *>(dlopen_trampoline_address);
}

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_DLOPEN_SHARED_DLOPEN_H_
