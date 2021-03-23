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

#include "asylo/platform/storage/utils/untrusted_file.h"

#include <sys/types.h>
#include <unistd.h>

#include "absl/status/status.h"
#include "asylo/util/posix_errors.h"

namespace asylo {

UntrustedFile::UntrustedFile(int fd) : fd_(fd) {}

UntrustedFile::~UntrustedFile() {
  Status result = Sync();
  if (!result.ok()) {
    LOG(ERROR) << "Unexpected failure in Sync() when closing an UntrustedFile: "
               << result;
  }
}

Status UntrustedFile::Read(void *buffer, off_t offset, size_t size) {
  off_t result = lseek(fd_, offset, SEEK_SET);
  if (result == -1) {
    return LastPosixError("lseek() failed in UntrustedFile::Read()");
  }

  size_t count = 0;
  while (count < size) {
    ssize_t result =
        read(fd_, reinterpret_cast<uint8_t *>(buffer) + count, size - count);
    if (result == 0) {
      return Status{error::NOT_FOUND, "read() failed in UntrustedFile::Read()"};
    }

    if (result < 0) {
      return LastPosixError("read() failed in UntrustedFile::Read()");
    }

    count += result;
  }

  return absl::OkStatus();
}

StatusOr<size_t> UntrustedFile::Size() const {
  off_t result = lseek(fd_, 0, SEEK_END);
  if (result == -1) {
    return LastPosixError("lseek() failed in UntrustedFile::Size()");
  }
  return result;
}

Status UntrustedFile::Sync() {
  if (fsync(fd_) != 0) {
    return LastPosixError("fsync() failed in UntrustedFile::Sync()");
  }
  return absl::OkStatus();
}

Status UntrustedFile::Write(const void *buffer, off_t offset, size_t size) {
  off_t result = lseek(fd_, offset, SEEK_SET);
  if (result == -1) {
    return LastPosixError("lseek() failed in UntrustedFile::Write()");
  }

  if (result < offset) {
    if (ftruncate(fd_, offset) != 0) {
      return LastPosixError("ftruncate() failed in UntrustedFile::Write()");
    }
    off_t result = lseek(fd_, offset, SEEK_SET);
    if (result == -1) {
      return LastPosixError(
          "lseek() failed after extending file in UntrustedFile::Write()");
    }
  }

  size_t count = 0;
  while (count < size) {
    ssize_t result = write(
        fd_, reinterpret_cast<const uint8_t *>(buffer) + count, size - count);

    if (result == 0) {
      return Status{error::RESOURCE_EXHAUSTED,
                    "write() failed in UntrustedFile::Write()"};
    }

    if (result < 0) {
      return LastPosixError("write() failed in UntrustedFile::Write()");
    }
    count += result;
  }

  return absl::OkStatus();
}

Status UntrustedFile::Truncate(size_t size) {
  if (ftruncate(fd_, size) != 0) {
    return LastPosixError("ftruncate() failed in UntrustedFile::Truncate()");
  }

  return absl::OkStatus();
}

}  // namespace asylo
