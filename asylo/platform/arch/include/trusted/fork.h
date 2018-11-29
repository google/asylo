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

#ifndef ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_FORK_H_
#define ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_FORK_H_

#include "asylo/enclave.pb.h"
#include "asylo/util/status.h"

namespace asylo {

// Copies enclave data/bss/heap and stack for the calling thread to untrusted
// memory.
Status TakeSnapshotForFork(SnapshotLayout *snapshot_layout);

// Copies the snapshot from untrusted memory to replace data/bss/heap and stack
// for the calling thread in the current enclave.
Status RestoreForFork(const SnapshotLayout &snapshot_layout);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_ARCH_INCLUDE_TRUSTED_FORK_H_
