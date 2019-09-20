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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_FORK_INTERNAL_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_FORK_INTERNAL_H_

#include <sys/types.h>

#include "asylo/enclave.pb.h"
#include "asylo/platform/primitives/sgx/fork.pb.h"
#include "asylo/util/status.h"

namespace asylo {

// Returns whether secure fork is supported in the current backend.
bool IsSecureForkSupported();

// Copies enclave data/bss/heap and stack for the calling thread to untrusted
// memory.
Status TakeSnapshotForFork(SnapshotLayout *snapshot_layout);

// Copies the snapshot from untrusted memory to replace data/bss/heap and stack
// for the calling thread in the current enclave. This method takes an |input|
// and |input_len|, and deserializes it into a SnapshotLayout protobuf. The
// protobuf is heap-allocated so we need to create the protobuf after the heap
// switch to avoid it being overwritten while restoring heap.
Status RestoreForFork(const char *input, size_t input_len);

// Does a handshake between the parent and child enclave, and parent encrypts
// and transfers the snapshot key to the child.
Status TransferSecureSnapshotKey(
    const ForkHandshakeConfig &fork_handshake_config);

// Saves the thread memory layout, including the base address and size of the
// stack/thread info of the calling TCS. Returns error Status if not in SGX
// hardware mode.
void SaveThreadLayoutForSnapshot();

// Sets fork request, which allows a snapshot of the enclave to be taken.
void SetForkRequested();

}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_FORK_INTERNAL_H_
