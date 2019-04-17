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

#include "asylo/platform/primitives/primitives.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/util/primitive_locks.h"
#include "asylo/platform/primitives/x86/spin_lock.h"
#include "asylo/util/error_codes.h"

extern "C" void *enc_untrusted_malloc(size_t size);
extern "C" void enc_untrusted_free(void *ptr);

namespace asylo {
namespace primitives {

namespace {

// Maximum number of supported enclave entry points.
constexpr size_t kEntryPointMax = 4096;

// Table of enclave entry handlers.
EntryHandler entry_table[kEntryPointMax];

// Lock protecting entry_table.
asylo_spinlock_t entry_table_lock = ASYLO_SPIN_LOCK_INITIALIZER;

}  // namespace

PrimitiveStatus TrustedPrimitives::RegisterEntryHandler(
    uint64_t trusted_selector, const EntryHandler &handler) {
  SpinLockGuard lock(&entry_table_lock);
  if (trusted_selector >= kEntryPointMax ||
      !entry_table[trusted_selector].IsNull()) {
    return {error::GoogleError::OUT_OF_RANGE,
            "Invalid selector in RegisterEntryHandler."};
  }

  entry_table[trusted_selector] = handler;
  return PrimitiveStatus::OkStatus();
}

void *TrustedPrimitives::UntrustedLocalAlloc(size_t size) {
  return enc_untrusted_malloc(size);
}

void TrustedPrimitives::UntrustedLocalFree(void *ptr) {
  enc_untrusted_free(ptr);
}

}  // namespace primitives
}  // namespace asylo
