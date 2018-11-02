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

#include "asylo/daemon/identity/attestation_domain.h"

#include <fcntl.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <array>
#include <cerrno>
#include <string>

#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/util/logging.h"
#include "asylo/util/posix_error_space.h"

namespace asylo {
namespace {

constexpr size_t kAttestationDomainSize = 16;
constexpr size_t kAttestationDomainHexSize = 2 * kAttestationDomainSize;

// Maximum number of attempts this library will make to read attestation-domain
// string from the attestation-domain file, in case insufficient bytes are
// present in the file. Such a situation can happen if the reader of the file is
// racing with the writer of the file.
constexpr int kMaxAttestationDomainReadAttempts = 5;

// Generates a new random machine id and writes it to |domain|. All
// encountered errors are fatal.
Status GenerateRandomAttestationDomain(std::string *domain) {
  std::array<char, kAttestationDomainSize> domain_internal;
  if (RAND_bytes(reinterpret_cast<uint8_t *>(domain_internal.data()),
                 domain_internal.size()) != 1) {
    return Status(error::GoogleError::INTERNAL,
                  absl::StrCat("RAND_bytes failed: ", BsslLastErrorString()));
  }
  domain->assign(domain_internal.data(), domain_internal.size());
  return Status::OkStatus();
}

// Creates a new machine id, and writes its hex representation to the file
// pointed to by the null-terminated C string |domain_file_path|, if the
// attestation-domain file does not exist.  On success, the function writes the
// new machine id to |domain|, and returns Status::OkStatus(). If the
// attestation-domain file already exists, then this function skips
// attestation-domain generation, and indicates this scenario by returning a
// status object containing error::PosixError::P_EEXIST. Callers are expected to
// detect this condition, and read-out the attestation-domain from the existing
// file. All other error conditions are fatal.
Status CreateAndWriteNewAttestationDomain(const char *domain_file_path,
                                          std::string *domain) {
  // Attempt to create the attestation-domain file.
  int fd = open(domain_file_path, O_EXCL | O_CREAT | O_RDWR);

  if (fd < 0) {
    if (errno == EEXIST) {
      return Status(error::PosixError::P_EEXIST, "File already exists");
    } else {
      return Status(static_cast<error::PosixError>(errno),
                    "Unexpected error while attempting to create "
                    "attestation-domain file");
    }
  }

  // Change the mode of the newly-created attestation-domain file to allow
  // read/write/execute from all users.
  if (fchmod(fd, S_IRWXU | S_IRWXG | S_IRWXO) != 0) {
    // Since the file cannot be created in a way that other users could
    // overwrite it, remove the file, and indicate an error.
    Status status(
        static_cast<error::PosixError>(errno),
        "Could not modify the permissions of attestation-domain file");
    close(fd);
    unlink(domain_file_path);
    return status;
  }

  // Create a random machine id, and write it to the attestation-domain file.
  Status status = GenerateRandomAttestationDomain(domain);
  if (!status.ok()) {
    close(fd);
    return status;
  }
  std::string domain_hex = absl::BytesToHexString(*domain);
  int result = write(fd, domain_hex.data(), domain_hex.size());
  if (result < 0 || static_cast<size_t>(result) < domain_hex.size()) {
    Status status = Status(
        static_cast<error::PosixError>(errno),
        absl::StrCat("Unexpected error while writing machine id. The file ",
                     domain_file_path, " may be damaged.",
                     "Please remove this file and try again."));
    close(fd);
    return status;
  }
  close(fd);
  return Status::OkStatus();
}

// Parses |domain| from the hex-formatted string view |domain_hex|. All
// encountered errors are fatal. The null-terminated C string
// |domain_file_path| is used for error-reporting purposes only.
Status ParseAttestationDomain(const char *domain_file_path,
                              absl::string_view domain_hex, std::string *domain) {
  for (const auto ch : domain_hex) {
    if (!absl::ascii_isxdigit(ch)) {
      return Status(
          error::GoogleError::INTERNAL,
          absl::StrCat("Invalid attestation-domain std::string. Remove the file ",
                       domain_file_path, " and try again."));
    }
  }
  *domain = absl::HexStringToBytes(domain_hex);
  return Status::OkStatus();
}

// Reads an existing |domain| from the file pointed to by the
// null-terminated C string |domain_file_path|. All encountered errors are
// fatal.
Status ReadExistingAttestationDomain(const char *domain_file_path,
                                     std::string *domain) {
  for (int attempt = 0; attempt < kMaxAttestationDomainReadAttempts;
       attempt++) {
    int fd = open(domain_file_path, O_RDONLY);
    if (fd < 0) {
      return Status(
          static_cast<error::PosixError>(errno),
          "Unexpected error while attempting to open attestation-domain file");
    }

    // Try reading one byte more than what is needed. A correctly formatted file
    // must have exactly kAttestationDomainHexSize bytes.
    std::array<char, kAttestationDomainHexSize + 1> domain_hex;
    int retval = read(fd, domain_hex.data(), domain_hex.size());
    close(fd);

    if (retval < 0) {
      return Status(
          static_cast<error::PosixError>(errno),
          "Unexpected error while attempting to read attestation-domain file");
    }
    if (static_cast<size_t>(retval) < kAttestationDomainHexSize) {
      // Could not read enough bytes. Most likely this is because this enclave
      // launch is racing against another enclave launch that is creating
      // domain. Sleep for 1 second and try again.
      sleep(1);
      continue;
    }
    if (static_cast<size_t>(retval) > kAttestationDomainHexSize) {
      return Status(error::GoogleError::INTERNAL, "Machine id is too long");
    }
    return ParseAttestationDomain(
        domain_file_path,
        absl::string_view(domain_hex.data(), kAttestationDomainHexSize),
        domain);
  }
  // Exhausted all read attempts without being able to read sufficient number of
  // bytes from the attestation-domain file--most likely the file is damaged.
  return Status(
      error::GoogleError::INTERNAL,
      absl::StrCat("Unexpected error while reading machine id. The file ",
                   domain_file_path, " may be damaged.",
                   "Please remove this file and try again."));
}

}  // namespace

Status GetAttestationDomain(const char *domain_file_path, std::string *domain) {
  // Atomically try to create a new machine id.
  Status status = CreateAndWriteNewAttestationDomain(domain_file_path, domain);
  if (!status.Is(error::PosixError::P_EEXIST)) {
    return status;
  }

  // File already exists. Read the attestation-domain from the file.
  return ReadExistingAttestationDomain(domain_file_path, domain);
}

}  // namespace asylo
