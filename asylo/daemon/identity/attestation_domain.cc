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
#include <openssl/hmac.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

// See Section 3 of RFC 4122: https://tools.ietf.org/html/rfc4122.
constexpr int kFormattedUuidSize = 36;
constexpr size_t kAttestationDomainSize = 16;

static_assert(kAttestationDomainSize <= kSha256DigestLength,
              "kAttestationDomainSize is too large");

constexpr char kBootUuidFile[] = "/proc/sys/kernel/random/boot_id";
constexpr uint8_t kAttestationDomainHmacData[] = "Asylo Attestation Domain";

// Reads and returns the machine UUID from kBootUuidFile.
StatusOr<std::string> GetPerBootUuid() {
  std::array<char, kFormattedUuidSize> uuid;
  int fd = open(kBootUuidFile, O_RDONLY);
  if (fd < 0) {
    return LastPosixError(absl::StrCat(
        "Unexpected error while attempting to open ", kBootUuidFile));
  }

  int retval = read(fd, uuid.data(), uuid.size());
  close(fd);

  if (retval < 0) {
    return LastPosixError(absl::StrCat(
        "Unexpected error while attempting to read ", kBootUuidFile));
  }
  if (retval != kFormattedUuidSize) {
    return Status(
        absl::StatusCode::kInternal,
        absl::StrFormat("Failed to read expected number of bytes from %s "
                        "(expected %d, got %d)",
                        kBootUuidFile, kFormattedUuidSize, retval));
  }

  return std::string(uuid.data(), uuid.size());
}

}  // namespace

StatusOr<std::string> GetAttestationDomain() {
  std::string boot_uuid;
  ASYLO_ASSIGN_OR_RETURN(boot_uuid, GetPerBootUuid());

  // We don't use the per-boot machine UUID as the attestation domain directly
  // because this value might be used by other protocols and we would be
  // exposing the raw UUID on the network. Instead, we derive an Asylo-specific
  // 16-byte value from the per-boot machine UUID using HMAC.
  const EVP_MD *digest = EVP_sha256();
  uint8_t mac[kSha256DigestLength];
  unsigned int attestation_domain_size = kSha256DigestLength;

  if (HMAC(digest, boot_uuid.data(), boot_uuid.size(),
           kAttestationDomainHmacData, sizeof(kAttestationDomainHmacData), mac,
           &attestation_domain_size) == nullptr) {
    return absl::InternalError(BsslLastErrorString());
  }

  // Truncate the MAC to the size of the attestation domain.
  return std::string(reinterpret_cast<const char *>(mac),
                     kAttestationDomainSize);
}

}  // namespace asylo
