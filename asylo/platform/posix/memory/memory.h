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

#ifndef ASYLO_PLATFORM_POSIX_MEMORY_MEMORY_H_
#define ASYLO_PLATFORM_POSIX_MEMORY_MEMORY_H_

#include <stddef.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// Gets the next available address on the switched heap.
void *GetSwitchedHeapNext();

// Gets the remaining size of the switched heap.
size_t GetSwitchedHeapRemaining();

// Temporarily switch malloc to allocate memory on user provided address space,
// with the base address |base| and size |size|. To switch back to normal heap,
// call it with |base| as a nullptr.
// This function is not thread-safe. This should only be called by fork during
// snapshotting/restoring while other threads are not allowed to enter the
// enclave.
void heap_switch(void *base, size_t size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ASYLO_PLATFORM_POSIX_MEMORY_MEMORY_H_
