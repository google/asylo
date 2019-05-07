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

#ifndef ASYLO_PLATFORM_STORAGE_UTILS_RANDOM_ACCESS_STORAGE_H_
#define ASYLO_PLATFORM_STORAGE_UTILS_RANDOM_ACCESS_STORAGE_H_

#include <sys/types.h>

#include <cstddef>

#include "asylo/util/asylo_macros.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// This class defines an abstract interface to persistent storage, modeled as a
// collection of variable-size records indexed by their byte offset into a flat
// array. This is provided to isolate the secure storage implementation from the
// underlying untrusted storage implementation.
class RandomAccessStorage {
 public:
  virtual ~RandomAccessStorage() = default;

  // Returns the size of the storage resource in bytes, or a Status if an I/O
  // error occurs.
  virtual StatusOr<size_t> Size() const = 0;

  // Reads |size| bytes of data from storage at a byte offset |offset|.
  virtual ASYLO_MUST_USE_RESULT Status Read(void *buffer, off_t offset,
                                            size_t size) = 0;

  // Writes |size| bytes to storage at a byte offset |offset|. If Size() if less
  // than |offset| + |size| then the resource is extended to a length of
  // |offset| + |size| bytes as-if by Truncate() before the write is performed.
  virtual ASYLO_MUST_USE_RESULT Status Write(const void *buffer, off_t offset,
                                             size_t size) = 0;

  // Commits pending writes to the underlying storage resource. This method is
  // provided for implementations where Write() does not commit to durable
  // storage synchronously, for instance because it writes via a user-space
  // cache or because writes are buffered by the kernel. Each implementation
  // should document what Sync() guarantees.
  virtual ASYLO_MUST_USE_RESULT Status Sync() = 0;

  // Truncates the storage resource to a specified length. If |size| is greater
  // than Size() then the underlying resource is extended to a length of |size|
  // bytes by appending zero-initialized storage.
  virtual ASYLO_MUST_USE_RESULT Status Truncate(size_t size) = 0;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_STORAGE_UTILS_RANDOM_ACCESS_STORAGE_H_
