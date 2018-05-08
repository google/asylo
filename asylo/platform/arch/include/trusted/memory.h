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

#ifndef ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_MEMORY_H_
#define ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_MEMORY_H_

#include <memory>

#include "asylo/platform/arch/include/trusted/host_calls.h"

namespace asylo {

// Deleter for untrusted memory for use with std::unique_ptr. Calls
// enc_untrusted_free() internally.
struct UntrustedDeleter {
  inline void operator()(void *ptr) const { enc_untrusted_free(ptr); }
};

template <typename T>
using UntrustedUniquePtr = std::unique_ptr<T, UntrustedDeleter>;

}  // namespace asylo

#endif  // ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_MEMORY_H_
