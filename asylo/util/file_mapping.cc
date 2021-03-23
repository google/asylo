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

#include "asylo/util/file_mapping.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstddef>
#include <cstring>

#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {

StatusOr<FileMapping> FileMapping::CreateFromFile(absl::string_view file_name) {
  // Create a copy of |file_name| that is definitely null-terminated so that it
  // can be passed to open(). This copy can be re-used by moving it into the
  // final FileMapping object at the end of the function. This ensures that we
  // only need to copy |file_name| once.
  std::string file_name_string(file_name.data(), file_name.size());
  void *buffer_ptr;
  size_t file_size;

  // Open the file.
  int fd = open(file_name_string.data(), O_RDONLY);
  if (fd == -1) {
    return LastPosixError(absl::StrCat("Failed to open ", file_name));
  }

  // Closing the file will not invalidate the memory mapping.
  Status close_status;
  {
    Cleanup close_fd([fd, file_name, &close_status]() {
      if (close(fd) == -1) {
        close_status =
            LastPosixError(absl::StrCat("Failed to close ", file_name));
      }
    });

    // Determine the size of the file.
    struct stat file_stat;
    if (fstat(fd, &file_stat) == -1) {
      return LastPosixError(
          absl::StrCat("Failed to determine the size of ", file_name));
    }
    file_size = static_cast<size_t>(file_stat.st_size);

    // Map the file into memory.
    buffer_ptr =
        mmap(nullptr, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (buffer_ptr == MAP_FAILED) {
      return LastPosixError(absl::StrCat("Failed to mmap ", file_name));
    }
  }

  ASYLO_RETURN_IF_ERROR(close_status);

  return FileMapping(
      std::move(file_name_string),
      absl::MakeSpan(reinterpret_cast<uint8_t *>(buffer_ptr), file_size));
}

FileMapping::~FileMapping() {
  if (mapped_region_.data() &&
      munmap(mapped_region_.data(), mapped_region_.size()) == -1) {
    LOG(FATAL) << absl::StrCat("Failed to unmap ", file_name_, ": ",
                               strerror(errno));
  }
}

void FileMapping::MoveFrom(FileMapping *other) {
  std::swap(file_name_, other->file_name_);
  std::swap(mapped_region_, other->mapped_region_);
}

}  // namespace asylo
