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

#include <stdlib.h>
#include <unistd.h>

#include "asylo/platform/primitives/sgx/fork_internal.h"
#include "asylo/platform/primitives/sgx/trusted_sgx.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/util/status.h"

namespace asylo {

bool IsSecureForkSupported() { return false; }

Status TakeSnapshotForFork(SnapshotLayout *snapshot_layout) {
  // Only supported in the SGX hardware backend.
  abort();
}

Status RestoreForFork(const char *input, size_t input_len) {
  // Only supported in the SGX hardware backend.
  abort();
}

Status TransferSecureSnapshotKey(
    const ForkHandshakeConfig &fork_handshake_config) {
  // Only supported in the SGX hardware backend.
  abort();
}

void SaveThreadLayoutForSnapshot() {
  // Only supported in the SGX hardware backend.
  abort();
}

void SetForkRequested() {
  // Only supported in the SGX hardware backend.
  abort();
}

pid_t enc_fork(const char *enclave_name) {
  // Block enclave entries while forking to make sure no other threads are
  // holding enclave entry/exit locks during fork().
  enc_block_entries();
  // Confirm that all other enclave entries are blocked before proceed to
  // fork(). All other enclave threads need to be blocked now, other than the
  // calling thread itself.
  // Timeout at 5 seconds.
  constexpr int timeout = 5;
  for (int i = 0;
       active_entry_count() > blocked_entry_count() + 1 && i < timeout; ++i) {
    sleep(1);
  }
  if (active_entry_count() > blocked_entry_count() + 1) {
    enc_unblock_entries();
    errno = EAGAIN;
    return -1;
  }
  pid_t pid =
      asylo::primitives::InvokeFork(enclave_name, /*restore_snapshot=*/false);
  enc_unblock_entries();
  return pid;
}

}  // namespace asylo
