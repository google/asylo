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

#ifndef ASYLO_PLATFORM_STORAGE_SECURE_ENCLAVE_STORAGE_SECURE_H_
#define ASYLO_PLATFORM_STORAGE_SECURE_ENCLAVE_STORAGE_SECURE_H_

// Secure Storage library for enclave. Implements secure IO methods to be
// invoked via POSIX IO API in the enclave environment. Assures authentication
// and confidentiality of stored data, backed by AE.

#include <sys/stat.h>
// IO syscall interface types.
#include <sys/types.h>

namespace asylo {
namespace platform {
namespace storage {

// Secure IO methods for respective POSIX IO API.

int secure_open(const char *pathname, int flags, ...);

// Note: POSIX leaves file offset on error undefined - thus, it is the client's
// responsibility to explicitly set file offset on error as the client desires.
ssize_t secure_read(int fd, void *buf, size_t count);

// Note: POSIX leaves file offset on error undefined - thus, it is the client's
// responsibility to explicitly set file offset on error as the client desires.
ssize_t secure_write(int fd, const void *buf, size_t count);

int secure_close(int fd);

off_t secure_lseek(int fd, off_t offset, int whence);

// |st->st_size| will be set to logical file size on success.
int secure_fstat(int fd, struct stat* st);

}  // namespace storage
}  // namespace platform
}  // namespace asylo

#endif  // ASYLO_PLATFORM_STORAGE_SECURE_ENCLAVE_STORAGE_SECURE_H_
