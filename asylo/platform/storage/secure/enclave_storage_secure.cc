/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/platform/storage/secure/enclave_storage_secure.h"

// IO syscall interface types.
#include <sys/types.h>

// IO syscall interface constants.
#include <fcntl.h>
#include <stdarg.h>

#include "asylo/util/logging.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/storage/secure/aead_handler.h"
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/platform/storage/utils/offset_translator.h"

namespace asylo {
namespace platform {
namespace storage {

int secure_open(const char *pathname, int flags, ...) {
  if ((flags & O_APPEND) || (flags & O_TRUNC)) {
    LOG(ERROR) << "Currently O_APPEND and O_TRUNC file creation flags are not "
                  "supported by the Secure Storage.";
    return -1;
  }

  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);
  }

  // Remove the O_SECURE flag, since it's not understood by any lower layers.
  flags &= ~O_SECURE;

  bool is_new_file = (enc_untrusted_access(pathname, F_OK) == -1);
  int fd = enc_untrusted_open(pathname, flags, mode);
  if (fd == -1) {
    LOG(ERROR) << "Failed to securely open file: " << pathname;
    return -1;
  }

  FdCloser fd_closer(fd, &enc_untrusted_close);

  // Set cursor to the logical offset of 0.
  if (secure_lseek(fd, 0, SEEK_SET) == -1) {
    LOG(ERROR) << "Failed to initialize cursor to the logical offset of 0, fd="
               << fd;
    return -1;
  }

  if (!AeadHandler::GetInstance().InitializeFile(fd, pathname, is_new_file)) {
    LOG(ERROR) << "Failed to initialize secure handling of file: " << pathname;
    return -1;
  }

  fd_closer.release();
  return fd;
}

ssize_t secure_read(int fd, void *buf, size_t count) {
  return AeadHandler::GetInstance().DecryptAndVerify(fd, buf, count);
}

ssize_t secure_write(int fd, const void *buf, size_t count) {
  return AeadHandler::GetInstance().EncryptAndPersist(fd, buf, count);
}

int secure_close(int fd) {
  bool finalize_result = AeadHandler::GetInstance().FinalizeFile(fd);
  return (finalize_result && enc_untrusted_close(fd) == 0) ? 0 : -1;
}

off_t secure_lseek(int fd, off_t offset, int whence) {
  if (offset < 0) {
    return -1;
  }

  const OffsetTranslator &offset_translator =
      AeadHandler::GetInstance().GetOffsetTranslator();

  // The net logical offset to which lseek has been requested.
  off_t logical_offset;
  switch (whence) {
    case SEEK_SET: {
      logical_offset = offset;
    } break;
    case SEEK_CUR: {
      off_t physical_cur_offset = enc_untrusted_lseek(fd, 0, SEEK_CUR);
      if (physical_cur_offset == -1) {
        LOG(ERROR) << "Failed to retrieve cursor offset on descriptor: " << fd;
        return -1;
      }
      off_t logical_cur_offset =
          offset_translator.PhysicalToLogical(physical_cur_offset);
      logical_offset = logical_cur_offset + offset;
    } break;
    case SEEK_END: {
      off_t logical_eof_offset =
          AeadHandler::GetInstance().GetLogicalFileSize(fd);
      logical_offset = logical_eof_offset + offset;
    } break;
    default: logical_offset = 0;  // Satisfy -Wmaybe-uninitialized
  }

  // The net physical offset that corresponds to the requested logical offset.
  off_t physical_offset = offset_translator.LogicalToPhysical(logical_offset);
  physical_offset = enc_untrusted_lseek(fd, physical_offset, SEEK_SET);
  if (physical_offset == -1) {
    LOG(ERROR) << "enclave_lseek failed, fd = " << fd
               << ", offset = " << offset;
    return -1;
  }
  return offset_translator.PhysicalToLogical(physical_offset);
}

int secure_fstat(int fd, struct stat *st) {
  int ret = enc_untrusted_fstat(fd, st);
  if (ret == 0) {
    // Rewrite to logical file size.
    st->st_size = AeadHandler::GetInstance().GetLogicalFileSize(fd);
  }
  return ret;
}

}  // namespace storage
}  // namespace platform
}  // namespace asylo
