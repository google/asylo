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

#ifndef ASYLO_PLATFORM_STORAGE_UTILS_UNTRUSTED_FILE_H_
#define ASYLO_PLATFORM_STORAGE_UTILS_UNTRUSTED_FILE_H_

#include "asylo/platform/storage/utils/random_access_storage.h"

namespace asylo {

// An implementation of RandomAccessStorage backed by a file.
class UntrustedFile : public RandomAccessStorage {
 public:
  // Constructs an UntrustedFile wrapping an open file descriptor. |fd| is
  // expected to support read(2), write(2), lseek(2), ftruncate(2), and
  // fsync(2).  |fd| remains owned by the caller and is not closed by the
  // UntrustedFile instance.
  explicit UntrustedFile(int fd);

  ~UntrustedFile();

  StatusOr<size_t> Size() const override;

  Status Read(void *buffer, off_t offset, size_t size) override;

  Status Write(const void *buffer, off_t offset, size_t size) override;

  // Synchronizes pending writes to the underlying file via fsync(2).
  Status Sync() override;

  Status Truncate(size_t size) override;

 private:
  int fd_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_STORAGE_UTILS_UNTRUSTED_FILE_H_
