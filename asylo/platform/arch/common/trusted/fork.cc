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

#include "asylo/platform/arch/include/trusted/fork.h"

#include <stdlib.h>

#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/util/status.h"

namespace asylo {

pid_t enc_fork(const char *enclave_name) {
  return enc_untrusted_fork(enclave_name, /*restore_required=*/false);
}

Status TakeSnapshotForFork(SnapshotLayout *snapshot_layout) {
  // Only supported in the SGX hardware backend.
  abort();
}

Status RestoreForFork(const SnapshotLayout &snapshot_layout) {
  // Only supported in the SGX hardware backend.
  abort();
}

}  // namespace asylo
