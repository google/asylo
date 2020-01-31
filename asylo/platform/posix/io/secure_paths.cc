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

#include "asylo/platform/posix/io/secure_paths.h"

#include <cerrno>
#include <cstdint>

#include "asylo/platform/crypto/gcmlib/gcm_cryptor.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/posix/io/io_manager.h"
#include "asylo/platform/storage/secure/aead_handler.h"
#include "asylo/platform/storage/secure/enclave_storage_secure.h"
#include "asylo/secure_storage.h"

using asylo::platform::crypto::gcmlib::kKeyLength;
using asylo::platform::storage::AeadHandler;

namespace asylo {
namespace io {

int IOContextSecure::Close() {
  return platform::storage::secure_close(host_fd_);
}

ssize_t IOContextSecure::Read(void *buf, size_t count) {
  return platform::storage::secure_read(host_fd_, buf, count);
}

ssize_t IOContextSecure::Write(const void *buf, size_t count) {
  return platform::storage::secure_write(host_fd_, buf, count);
}

int IOContextSecure::LSeek(off_t offset, int whence) {
  return platform::storage::secure_lseek(host_fd_, offset, whence);
}

int IOContextSecure::FSync() { return enc_untrusted_fsync(host_fd_); }

int IOContextSecure::FStat(struct stat *st) {
  return platform::storage::secure_fstat(host_fd_, st);
}

int IOContextSecure::Isatty() { return enc_untrusted_isatty(host_fd_); }

int IOContextSecure::Ioctl(int request, void *argp) {
  switch (request) {
    case ENCLAVE_STORAGE_SET_KEY: {
      struct key_info *ioctl_param = reinterpret_cast<struct key_info *>(argp);
      return AeadHandler::GetInstance().SetMasterKey(
          host_fd_, ioctl_param->data, ioctl_param->length);
    }
    default:
      if (argp != nullptr) {
        errno = ENOSYS;
        return -1;
      }
      return enc_untrusted_ioctl1(host_fd_, request);
  }

  return -1;
}

}  // namespace io
}  // namespace asylo
