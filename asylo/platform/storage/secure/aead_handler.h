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

#ifndef ASYLO_PLATFORM_STORAGE_SECURE_AEAD_HANDLER_H_
#define ASYLO_PLATFORM_STORAGE_SECURE_AEAD_HANDLER_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <unordered_map>

#include "absl/base/attributes.h"
#include "absl/synchronization/mutex.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/platform/crypto/gcmlib/gcm_cryptor.h"
#include "asylo/platform/storage/secure/authenticated_dictionary.h"
#include "asylo/platform/storage/secure/ctmmt_authenticated_dictionary.h"
#include "asylo/platform/storage/utils/offset_translator.h"

namespace asylo {
namespace platform {
namespace storage {

using crypto::gcmlib::GcmCryptor;
using crypto::gcmlib::GcmCryptorKey;
using crypto::gcmlib::kKeyLength;
using crypto::gcmlib::kTagLength;
using crypto::gcmlib::kTokenLength;

// Length of file blocks to encrypt/decrypt.
constexpr size_t kBlockLength = 128;
using Block = UnsafeBytes<kBlockLength>;

// Length of the file digest (of the AD root).
constexpr int64_t kRootHashLength = 32;

// Length of the hash of the file digest (of the AD root).
constexpr int64_t kFileHashLength = 16;

// Constants for the secure block structure - the secure block consists of
// the ciphertext of the same length as the original plaintext, followed by the
// integrity tag, followed by the encryption token.
constexpr size_t kCipherBlockLength = kBlockLength + kTagLength;
constexpr size_t kSecureBlockLength = kCipherBlockLength + kTokenLength;

using FileHash = UnsafeBytes<kFileHashLength>;
using FileDigest = UnsafeBytes<kRootHashLength>;

// Authenticated Encryption with Associated Data (AEAD) handler class. Maintains
// AEAD metadata for file data when a securely handled file is modified from the
// enclave. Encapsulates operations on file's integrity metadata based on the
// supplied file data. Uses enclave-to-host IO delegates to propagate IO calls
// over the enclave boundary to access file storage outside the enclave.
//
// Tracked feature work:
//
class AeadHandler {
 public:
  static AeadHandler &GetInstance() {
    static AeadHandler *instance = new AeadHandler;
    return *instance;
  }

  // Loads integrity metadata, initializes integrity assurance for a newly
  // opened file, returns false on failure. Does not modify the state of the
  // file descriptor. By contract, absolute (canonical) |path_name| is expected.
  // The function performs a weak validation that the path is canonical.
  bool InitializeFile(int fd, const char *path_name, bool is_new_file)
      ABSL_LOCKS_EXCLUDED(mu_);

  // Decrypts read data in-place, verifies data has not been tampered with,
  // returns the size of data verified, or -1 on failure.
  ssize_t DecryptAndVerify(int fd, void *buf, size_t count)
      ABSL_LOCKS_EXCLUDED(mu_);

  // Encrypts data and generates integrity metadata for it in memory, writes
  // encrypted data to disk, returns the size of data written, or -1 on failure.
  ssize_t EncryptAndPersist(int fd, const void *buf, size_t count)
      ABSL_LOCKS_EXCLUDED(mu_);

  // Frees resources used to assure integrity of an opened file, persists
  // integrity metadata to a designated location on disk, returns false on
  // failure. Does not modify the state of the file descriptor.
  bool FinalizeFile(int fd) ABSL_LOCKS_EXCLUDED(mu_);

  // Sets the master key for a newly opened file.
  int SetMasterKey(int fd, const uint8_t *key_data, uint32_t key_length)
      ABSL_LOCKS_EXCLUDED(mu_);

  // Returns the logical file size, or -1 on failure.
  off_t GetLogicalFileSize(int fd) ABSL_LOCKS_EXCLUDED(mu_);

  const OffsetTranslator &GetOffsetTranslator() const;

 private:
  // Structure represents the file header layout.
  struct FileHeader {
    // Hash of the DataDigest.
    FileHash file_hash;

    // Logical file size - is incorporated into DataDigest and is protected by
    // FileHash.
    size_t file_size;

    // Returns the address of the FileHeader instance.
    uint8_t *data() { return file_hash.data(); }
  } ABSL_ATTRIBUTE_PACKED;

  // Structure represents the file data digest from which the file hash used for
  // integrity validation is calculated.
  struct DataDigest {
    // AD digest of the file data.
    FileDigest file_digest;

    // Logical file size.
    size_t file_size;

    // Returns the address of the DataDigest instance.
    uint8_t *data() { return file_digest.data(); }
  } ABSL_ATTRIBUTE_PACKED;

  // File (data set) control structure for an opened file.
  struct FileControl {
    const std::string path;
    size_t logical_size;
    bool is_new;
    bool is_deserialized;
    std::unique_ptr<AuthenticatedDictionary> ad;
    std::string zero_hash;
    std::unique_ptr<GcmCryptorKey> master_key;

    // Mutex for protecting FileControl instance.
    absl::Mutex mu;

    FileControl(const char *path_name, bool is_new_file)
        : path(path_name),
          logical_size(0),
          is_new(is_new_file),
          is_deserialized(false),
          ad(absl::make_unique<CTMMTAuthenticatedDictionary>()) {
      UnsafeBytes<kTagLength> tag;
      memset(tag.data(), 0, kTagLength);
      std::string tag_string(reinterpret_cast<char *>(tag.data()), kTagLength);
      zero_hash = ad->LeafHash(tag_string);
    }

    // NOTE: The physical_size is on block granularity because the block
    // metadata is placed after the block data, hence, only full blocks are
    // written - there are no partial blocks.
    size_t physical_size() {
      return sizeof(FileHeader) + ad->LeafCount() * kSecureBlockLength;
    }
  };

  AeadHandler();
  AeadHandler(AeadHandler const &) = delete;
  void operator=(AeadHandler const &) = delete;

  // Loads and validates integrity metadata, returns false on failure.
  bool Deserialize(FileControl *file_ctrl)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(file_ctrl->mu);

  // Retrieves logical cursor offset associated with a file descriptor |fd|.
  // Returns false on failure.
  bool RetrieveLogicalOffset(int fd, off_t *logical_offset) const;

  // Updates digest of the file data in the secure file header.
  bool UpdateDigest(FileControl *file_ctrl, const GcmCryptor &cryptor) const
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(file_ctrl->mu);

  // Returns an instance of GcmCryptor associated with a file, or nullptr if was
  // not able to retrieve. The caller does not own the instance.
  GcmCryptor *GetGcmCryptor(const FileControl &file_ctrl) const
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(file_ctrl.mu);

  // Similar to DecryptAndVerify, but is called by internal implementation, and
  // as such does not take a file lock. The cursor associated with the file
  // descriptor |fd| is expected to be at the position of |logical_offset|.
  ssize_t DecryptAndVerifyInternal(int fd, void *buf, size_t count,
                                   const FileControl &file_ctrl,
                                   off_t logical_offset) const
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(file_ctrl.mu);

  // Reads a single full block of a file at a specified logical offset. Returns
  // false on failure.
  bool ReadFullBlock(const FileControl &file_ctrl, off_t logical_offset,
                     Block *block) const
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(file_ctrl.mu);

  // Map of file (data set) controls for opened files keyed on int identity of
  // files. Avoid using absl based containers which may perform system calls, as
  // this class is expected to be used in trusted primitives layer where
  // system calls might not be available.
  std::unordered_map<int, std::shared_ptr<FileControl>> fmap_
      ABSL_GUARDED_BY(mu_);

  // Map of file (data set) controls for opened files keyed on string paths of
  // files. Avoid using absl based containers which may perform system calls, as
  // this class is expected to be used in trusted primitives layer where system
  // calls might not be available.
  std::unordered_map<std::string, std::shared_ptr<FileControl>> opened_files_
      ABSL_GUARDED_BY(mu_);

  // An instance that performs operations on untrusted file offset.
  std::unique_ptr<OffsetTranslator> offset_translator_;

  // Mutex for protecting map members of the class.
  absl::Mutex mu_;
};

}  // namespace storage
}  // namespace platform
}  // namespace asylo

#endif  // ASYLO_PLATFORM_STORAGE_SECURE_AEAD_HANDLER_H_
