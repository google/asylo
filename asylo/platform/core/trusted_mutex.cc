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

#include "asylo/platform/core/trusted_mutex.h"

#include <cstdio>
#include <cstdlib>

#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"

namespace asylo {

TrustedMutex::TrustedMutex(bool is_recursive)
    : untrusted_mutex_(is_recursive), trusted_spin_lock_(is_recursive) {}

void TrustedMutex::Lock() {
  untrusted_mutex_.Lock();
  if (!trusted_spin_lock_.TryLock()) {
    abort();
  }
}

bool TrustedMutex::Owned() const { return trusted_spin_lock_.Owned(); }

bool TrustedMutex::TryLock() {
  if (!untrusted_mutex_.TryLock()) {
    return false;
  }

  if (!trusted_spin_lock_.TryLock()) {
    primitives::TrustedPrimitives::BestEffortAbort(
        "TrustedMutex::TryLock UntrustedMutex and TrustedSpinLock disagree on "
        "TryLock.");
  }
  return true;
}

void TrustedMutex::Unlock() {
  trusted_spin_lock_.Unlock();
  untrusted_mutex_.Unlock();
}

}  // namespace asylo
