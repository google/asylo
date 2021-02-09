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

// Implementation of AEAD handler class.

#include "asylo/platform/storage/secure/aead_handler.h"

// IO syscall interface constants.
#include <fcntl.h>

#include <iomanip>
#include <memory>

#include "absl/strings/escaping.h"
#include "absl/synchronization/mutex.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/storage/utils/fd_closer.h"

namespace asylo {
namespace platform {
namespace storage {

using crypto::gcmlib::GcmCryptor;
using crypto::gcmlib::GcmCryptorRegistry;

namespace {

// Perform a weak validation that the path is canonical.
bool IsPathNameValid(const char *path_name) {
  return path_name && strlen(path_name) && path_name[0] == '/';
}

bool is_transient_error(int err) { return (err == EAGAIN) || (err == EINTR); }

// Returns -1 on failure, or min(|len|, bytes to EOF) on success.
ssize_t read_all(int fd, void *buf, size_t len) {
  size_t bytes_to_read = len;
  size_t offset = 0;

  while (bytes_to_read > 0) {
    ssize_t bytes_read;
    do {
      bytes_read = enc_untrusted_read(fd, static_cast<uint8_t *>(buf) + offset,
                                      bytes_to_read);
    } while ((bytes_read == -1) && is_transient_error(errno));
    if (bytes_read == -1) {
      return -1;
    }
    if (bytes_read == 0) {
      return offset;
    }

    bytes_to_read -= bytes_read;
    offset += bytes_read;
  }

  return offset;
}

// Returns -1 on failure, or |len| on success.
ssize_t write_all(int fd, const void *buf, size_t len) {
  size_t bytes_to_write = len;
  size_t offset = 0;

  while (bytes_to_write > 0) {
    ssize_t bytes_written;
    do {
      bytes_written = enc_untrusted_write(
          fd, static_cast<const uint8_t *>(buf) + offset, bytes_to_write);
    } while ((bytes_written == -1) && is_transient_error(errno));
    if (bytes_written == -1) {
      return -1;
    }

    bytes_to_write -= bytes_written;
    offset += bytes_written;
  }

  // Coherence check.
  if (offset != len) {
    return -1;
  }

  return offset;
}

// Returns offset to the plaintext buffer associated with the |block_index| of
// a full block.
const uint8_t *GetPlaintextBuffer(size_t first_partial_block_bytes_count,
                                  int64_t block_index, const void *buf) {
  const uint8_t *plaintext_data = reinterpret_cast<const uint8_t *>(buf);
  if (first_partial_block_bytes_count > 0) {
    if (block_index > 0) {
      plaintext_data += first_partial_block_bytes_count;
    }
    if (block_index > 1) {
      plaintext_data += (block_index - 1) * kBlockLength;
    }
  } else {
    plaintext_data += block_index * kBlockLength;
  }

  return plaintext_data;
}

uint8_t *GetPlaintextBuffer(size_t first_partial_block_bytes_count,
                            int64_t block_index, void *buf) {
  return const_cast<uint8_t *>(
      GetPlaintextBuffer(first_partial_block_bytes_count, block_index,
                         const_cast<const void *>(buf)));
}

}  // namespace

using Tag = UnsafeBytes<kTagLength>;
using Token = UnsafeBytes<kTokenLength>;
using Block = UnsafeBytes<kBlockLength>;
using Ciphertext = UnsafeBytes<kCipherBlockLength>;
using SecureBlock = UnsafeBytes<kSecureBlockLength>;

using TagView = ByteContainerView;
using TokenView = ByteContainerView;
using BlockView = ByteContainerView;
using CiphertextView = ByteContainerView;
using SecureBlockView = ByteContainerView;

AeadHandler::AeadHandler()
    : offset_translator_(OffsetTranslator::Create(
          sizeof(FileHeader), kBlockLength, kSecureBlockLength)) {}

bool AeadHandler::Deserialize(FileControl *file_ctrl) {
  if (!file_ctrl) {
    errno = EINVAL;
    return false;
  }
  file_ctrl->mu.AssertHeld();

  const GcmCryptor *cryptor = GetGcmCryptor(*file_ctrl);
  if (!cryptor) {
    return false;
  }

  if (file_ctrl->is_new) {
    if (!UpdateDigest(file_ctrl, *cryptor)) {
      LOG(ERROR) << "Failed to update header on a new file, path="
                 << file_ctrl->path << ", errno = " << errno;
      return false;
    }

    file_ctrl->is_new = false;

    // No metadata to collect.
    return true;
  }

  // Rebuild the Merkle tree.
  int fd = enc_untrusted_open(file_ctrl->path.c_str(), O_RDONLY);
  if (fd == -1) {
    LOG(ERROR) << "Failed to open file for collecting security metadata, path="
               << file_ctrl->path << ", errno = " << errno;
    return false;
  }

  FdCloser fd_closer(fd, &enc_untrusted_close);

  // Read the header with digest.
  FileHeader file_header;
  ssize_t bytes_read = read_all(fd, file_header.data(), sizeof(FileHeader));
  if (bytes_read != sizeof(FileHeader)) {
    LOG(ERROR) << "Failed to read the file header, bytes read = " << bytes_read;
    return false;
  }

  // In order to validate the integrity metadata and the file size have to first
  // collect integrity metadata across the file using the initially untrusted
  // value of the file size - then validation of the hash of the file digest
  // confirms validity of both the file size and the integrity metadata.
  const int64_t blocks_count =
      (file_header.file_size + kBlockLength - 1) / kBlockLength;
  Tag tag;
  for (int64_t block_index = 0; block_index < blocks_count; block_index++) {
    off_t offset = enc_untrusted_lseek(fd, kBlockLength, SEEK_CUR);
    if (offset == -1) {
      LOG(ERROR)
          << "Failed lseek past block when collecting integrity metadata.";
      return false;
    }

    bytes_read = read_all(fd, tag.data(), kTagLength);
    if (bytes_read != kTagLength) {
      LOG(ERROR) << "Failed to read integrity metadata, bytes_read="
                 << bytes_read;
      return false;
    }

    std::string tag_string(reinterpret_cast<char *>(tag.data()), kTagLength);
    VLOG(2) << "Adding auth tag as leaf to rebuild Merkle tree: "
            << absl::BytesToHexString(tag_string);
    file_ctrl->ad->AddLeaf(tag_string);

    offset = enc_untrusted_lseek(fd, kTokenLength, SEEK_CUR);
    if (offset == -1) {
      LOG(ERROR)
          << "Failed lseek past token when collecting integrity metadata.";
      return false;
    }
  }

  VLOG(2) << "Pushed block auth tags on initialization.";

  // Prepare file data digest.
  DataDigest data_digest;
  std::copy_n(
      reinterpret_cast<const uint8_t *>(file_ctrl->ad->CurrentRoot().data()),
      kRootHashLength, data_digest.data());
  data_digest.file_size = file_header.file_size;

  // Validate AD root and the file size.
  FileHash new_hash;
  if (!cryptor->GetAuthTag(new_hash.data(), data_digest.data(),
                           sizeof(DataDigest))) {
    LOG(ERROR) << "Failed to generate CMAC for integrity verification, root="
               << file_ctrl->ad->CurrentRoot();
    return false;
  }

  if (new_hash != file_header.file_hash) {
    LOG(ERROR) << "Failure validating integrity root for file "
               << file_ctrl->path << ", current root: "
               << absl::BytesToHexString(file_ctrl->ad->CurrentRoot());
    return false;
  }

  file_ctrl->logical_size = file_header.file_size;
  return true;
}

bool AeadHandler::InitializeFile(int fd, const char *path_name,
                                 bool is_new_file) {
  if (!IsPathNameValid(path_name)) {
    LOG(ERROR) << "Invalid input when initializing file, path_name="
               << path_name;
    errno = EINVAL;
    return false;
  }

  absl::MutexLock global_lock(&mu_);

  auto fd_it = fmap_.find(fd);
  if (fd_it != fmap_.end()) {
    LOG(ERROR) << "Attempt made to initialize already initialized file, fd="
               << fd << ", path_name = " << path_name
               << ", is_new_file = " << is_new_file;
    errno = EEXIST;
    return false;
  }

  VLOG(2) << "Initializing secure file, fd = " << fd
          << ", path_name = " << path_name;
  auto path_it = opened_files_.find(path_name);
  std::shared_ptr<FileControl> file_ctrl =
      (path_it == opened_files_.end())
          ? std::make_shared<FileControl>(path_name, is_new_file)
          : path_it->second;
  fmap_.emplace(fd, file_ctrl);
  opened_files_.emplace(path_name, file_ctrl);

  return true;
}

bool AeadHandler::RetrieveLogicalOffset(int fd, off_t *logical_offset) const {
  if (fd < 0) {
    errno = EINVAL;
    return false;
  }

  off_t physical_offset = enc_untrusted_lseek(fd, 0, SEEK_CUR);
  if (physical_offset == -1) {
    LOG(ERROR) << "Failed to retrieve SEEK_CUR offset on descriptor: " << fd;
    return false;
  }

  *logical_offset = offset_translator_->PhysicalToLogical(physical_offset);
  if (*logical_offset == OffsetTranslator::kInvalidOffset) {
    LOG(ERROR) << "The file is corrupted, fd = " << fd;
    return false;
  }

  return true;
}

GcmCryptor *AeadHandler::GetGcmCryptor(const FileControl &file_ctrl) const {
  file_ctrl.mu.AssertHeld();
  if (!file_ctrl.master_key) {
    LOG(ERROR) << "Master key has not been set, path = " << file_ctrl.path;
    return nullptr;
  }

  GcmCryptor *cryptor = GcmCryptorRegistry::GetInstance().GetGcmCryptor(
      kBlockLength, *file_ctrl.master_key);
  if (!cryptor) {
    LOG(ERROR) << "Unable to instantiate GCM cryptor.";
  }

  return cryptor;
}

ssize_t AeadHandler::DecryptAndVerify(int fd, void *buf, size_t count) {
  if (!buf) {
    errno = EINVAL;
    return -1;
  }

  off_t logical_offset;
  if (!RetrieveLogicalOffset(fd, &logical_offset)) {
    return -1;
  }

  std::shared_ptr<FileControl> file_ctrl;
  {
    absl::MutexLock global_lock(&mu_);

    auto entry = fmap_.find(fd);
    if (entry == fmap_.end()) {
      LOG(ERROR) << "Attempt made to read from an unopened file, fd = " << fd;
      errno = ENOENT;
      return -1;
    }

    file_ctrl = entry->second;
  }

  absl::MutexLock lock(&file_ctrl->mu);
  return DecryptAndVerifyInternal(fd, buf, count, *file_ctrl, logical_offset);
}

ssize_t AeadHandler::DecryptAndVerifyInternal(int fd, void *buf, size_t count,
                                              const FileControl &file_ctrl,
                                              off_t logical_offset) const {
  file_ctrl.mu.AssertHeld();
  if (count == 0) {
    return 0;
  }

  // Check for logical EOF.
  if (logical_offset >= file_ctrl.logical_size) {
    return 0;
  }

  // Do not read beyond the EOF.
  if (logical_offset + count >= file_ctrl.logical_size) {
    count = file_ctrl.logical_size - logical_offset;
  }

  // Determine data breakdown into logical blocks.
  size_t first_partial_block_bytes_count;
  size_t last_partial_block_bytes_count;
  size_t full_inclusive_blocks_bytes_count;
  offset_translator_->ReduceLogicalRangeToFullLogicalBlocks(
      logical_offset, count, &first_partial_block_bytes_count,
      &last_partial_block_bytes_count, &full_inclusive_blocks_bytes_count);

  // Use single read buffer to minimize the number of read calls to the host.
  std::vector<uint8_t> buffer;
  const size_t physical_bytes_count =
      (full_inclusive_blocks_bytes_count / kBlockLength) * kSecureBlockLength;
  buffer.resize(physical_bytes_count);

  // Move cursor to the first full block to read.
  const off_t first_logical_block_offset =
      (first_partial_block_bytes_count > 0)
          ? (logical_offset + first_partial_block_bytes_count - kBlockLength)
          : logical_offset;
  const off_t first_physical_block_offset =
      offset_translator_->LogicalToPhysical(first_logical_block_offset);
  if (first_partial_block_bytes_count > 0) {
    off_t offset =
        enc_untrusted_lseek(fd, first_physical_block_offset, SEEK_SET);
    if (offset == -1) {
      LOG(ERROR)
          << "Failed lseek to the fist block offset when reading file data.";
      return -1;
    }
  }

  // Perform the read. Read may have been requested beyond EOF - cannot require
  // that bytes_read is equal to physical_bytes_count. The read was not
  // requested at EOF - checked this above.
  ssize_t bytes_read =
      enc_untrusted_read(fd, buffer.data(), physical_bytes_count);
  if (bytes_read <= 0) {
    LOG(ERROR) << "Cannot verify data - data has not been read, fd = " << fd;
    return -1;
  }

  // Process only complete blocks read, since need per-block metadata to decrypt
  // the block.
  bytes_read = (bytes_read / kSecureBlockLength) * kSecureBlockLength;
  if (bytes_read == 0) {
    LOG(ERROR) << "Cannot verify data - data has not been read, fd = " << fd;
    return -1;
  }

  // Move cursor to the position of the end of the read range.
  off_t new_cur_logical_offset = logical_offset + count;
  if (bytes_read != physical_bytes_count) {
    int64_t blocks_not_read =
        (physical_bytes_count - bytes_read) / kSecureBlockLength;
    if (last_partial_block_bytes_count > 0) {
      new_cur_logical_offset -= last_partial_block_bytes_count;
      blocks_not_read--;
    }
    new_cur_logical_offset -= blocks_not_read * kBlockLength;
  }
  const off_t new_cur_physical_offset =
      offset_translator_->LogicalToPhysical(new_cur_logical_offset);
  off_t offset = enc_untrusted_lseek(fd, new_cur_physical_offset, SEEK_SET);
  if (offset == -1) {
    LOG(ERROR) << "Failed lseek to the end of read range.";
    return -1;
  }

  GcmCryptor *cryptor = GetGcmCryptor(file_ctrl);
  if (!cryptor) {
    return -1;
  }

  // Cycle through blocks.
  const int64_t blocks_read = bytes_read / kSecureBlockLength;
  const int64_t blocks_read_max = physical_bytes_count / kSecureBlockLength;
  const off_t first_block_index =
      (first_physical_block_offset - sizeof(FileHeader)) / kSecureBlockLength;
  size_t read_count = 0;
  for (int64_t block_index = 0; block_index < blocks_read; block_index++) {
    const size_t merkle_block_idx = first_block_index + block_index + 1;

    uint8_t *plaintext_data =
        GetPlaintextBuffer(first_partial_block_bytes_count, block_index, buf);

    // Detect full blocks that belong to sparse regions in the file - no need to
    // decrypt.
    if (file_ctrl.ad->LeafHash(merkle_block_idx) == file_ctrl.zero_hash) {
      VLOG(2) << "A sparse region block detected.";
      memset(plaintext_data, 0, kBlockLength);
      read_count += kBlockLength;
      continue;
    }

    CiphertextView ciphertext(buffer.data() + block_index * kSecureBlockLength,
                              kCipherBlockLength);
    VLOG(2) << "Ciphertext read: "
            << absl::BytesToHexString(absl::string_view(
                   reinterpret_cast<const char *>(ciphertext.data()),
                   kCipherBlockLength));

    TagView tag(buffer.data() + block_index * kSecureBlockLength + kBlockLength,
                kTagLength);
    VLOG(2) << "Auth tag read: "
            << absl::BytesToHexString(absl::string_view(
                   reinterpret_cast<const char *>(tag.data()), kTagLength));

    TokenView token(
        buffer.data() + block_index * kSecureBlockLength + kCipherBlockLength,
        kTokenLength);
    VLOG(2) << "Token read: "
            << absl::BytesToHexString(absl::string_view(
                   reinterpret_cast<const char *>(token.data()), kTokenLength));

    // Note: Verifying integrity tag will be replaced with integrity
    // verification against AD root if/when AD tree will be stored in a file
    // (i.e. if/when optimizing integrity assurance for large files).
    if (file_ctrl.ad->LeafHash(merkle_block_idx) !=
        file_ctrl.ad->LeafHash(std::string(
            reinterpret_cast<const char *>(tag.data()), kTagLength))) {
      LOG(ERROR) << "Integrity verification failed, fd = " << fd;
      return -1;
    }

    // Bounce block for reading partial blocks at the ends of the full range.
    Block bounce_block;
    // Target for decryption - bounce block or the supplied buffer.
    uint8_t *decrypt_target;
    // Determine the target depending on whether the read block is at the end of
    // the full range.
    if ((block_index == 0 && first_partial_block_bytes_count > 0) ||
        (block_index == blocks_read_max - 1 &&
         last_partial_block_bytes_count > 0)) {
      decrypt_target = bounce_block.data();
    } else {
      decrypt_target = plaintext_data;
    }

    // Decrypt the block.
    if (!cryptor->DecryptBlock(ciphertext.data(), token.data(),
                               decrypt_target)) {
      LOG(ERROR) << "Decryption failed, fd = " << fd;
      return -1;
    }

    // Copy content from the bounce buffer, if used. Increment the count of read
    // bytes.
    if (block_index == 0 && first_partial_block_bytes_count > 0) {
      std::copy_n(
          bounce_block.begin() + kBlockLength - first_partial_block_bytes_count,
          first_partial_block_bytes_count, plaintext_data);
      read_count += first_partial_block_bytes_count;
    } else if (block_index == blocks_read_max - 1 &&
               last_partial_block_bytes_count > 0) {
      std::copy_n(bounce_block.begin(), last_partial_block_bytes_count,
                  plaintext_data);
      read_count += last_partial_block_bytes_count;
    } else {
      read_count += kBlockLength;
    }
  }

  VLOG(2) << "Verified read blocks, blocks_read = " << blocks_read
          << ", bytes_read = " << bytes_read;
  return read_count;
}

bool AeadHandler::UpdateDigest(FileControl *file_ctrl,
                               const GcmCryptor &cryptor) const {
  if (!file_ctrl) {
    errno = EINVAL;
    return false;
  }
  file_ctrl->mu.AssertHeld();

  int fd = enc_untrusted_open(file_ctrl->path.c_str(), O_WRONLY);
  if (fd == -1) {
    LOG(ERROR) << "Failed to open file to save data digest, path="
               << file_ctrl->path << ", errno = " << errno;
    return false;
  }

  FdCloser fd_closer(fd, &enc_untrusted_close);

  std::string root = file_ctrl->ad->CurrentRoot();
  if (root.size() != kRootHashLength) {
    LOG(ERROR) << "Unexpected size of root hash encountered, size="
               << root.size();
    return false;
  }

  // Prepare file data digest.
  DataDigest data_digest;
  std::copy_n(reinterpret_cast<const uint8_t *>(root.data()), kRootHashLength,
              data_digest.data());
  data_digest.file_size = file_ctrl->logical_size;

  FileHeader header;
  if (!cryptor.GetAuthTag(header.data(), data_digest.data(),
                          sizeof(DataDigest))) {
    LOG(ERROR) << "Failed to generate CMAC, root = " << root;
    return false;
  }
  header.file_size = file_ctrl->logical_size;

  VLOG(2) << "Updating the digest for file: " << file_ctrl->path
          << ", root hash: " << absl::BytesToHexString(root);
  ssize_t bytes_written = write_all(fd, header.data(), sizeof(FileHeader));
  if (bytes_written != sizeof(FileHeader)) {
    LOG(ERROR) << "Failed to write full digest to file, path="
               << file_ctrl->path << ", bytes written = " << bytes_written;
    return false;
  }

  if (!fd_closer.reset()) {
    LOG(ERROR) << "Failed to close the file after digest update, path="
               << file_ctrl->path;
    return false;
  }

  return true;
}

bool AeadHandler::ReadFullBlock(const FileControl &file_ctrl,
                                off_t logical_offset, Block *block) const {
  file_ctrl.mu.AssertHeld();
  if (logical_offset < 0 || logical_offset % kBlockLength != 0) {
    errno = EINVAL;
    return false;
  }

  int fd = enc_untrusted_open(file_ctrl.path.c_str(), O_RDONLY);
  if (fd == -1) {
    LOG(ERROR) << "Failed to open file to read a block, path=" << file_ctrl.path
               << ", errno = " << errno;
    return false;
  }

  FdCloser fd_closer(fd, &enc_untrusted_close);

  off_t physical_offset = offset_translator_->LogicalToPhysical(logical_offset);
  off_t offset = enc_untrusted_lseek(fd, physical_offset, SEEK_SET);
  if (offset == -1) {
    LOG(ERROR) << "Failed lseek when reading a full block.";
    return false;
  }

  ssize_t bytes_read = DecryptAndVerifyInternal(fd, block->data(), kBlockLength,
                                                file_ctrl, logical_offset);
  if (bytes_read == -1) {
    return -1;
  }

  if (bytes_read < kBlockLength) {
    memset(block->data() + bytes_read, 0, kBlockLength - bytes_read);
  }

  return true;
}

ssize_t AeadHandler::EncryptAndPersist(int fd, const void *buf, size_t count) {
  if (!buf) {
    errno = EINVAL;
    return -1;
  }

  off_t logical_offset;
  if (!RetrieveLogicalOffset(fd, &logical_offset)) {
    return -1;
  }

  std::shared_ptr<FileControl> file_ctrl;
  {
    absl::MutexLock global_lock(&mu_);

    auto entry = fmap_.find(fd);
    if (entry == fmap_.end()) {
      LOG(ERROR) << "Attempt made to write to an unopened file, fd = " << fd;
      errno = ENOENT;
      return -1;
    }

    file_ctrl = entry->second;
  }

  if (count == 0) {
    return 0;
  }

  absl::MutexLock lock(&file_ctrl->mu);

  // Determine data breakdown into logical blocks.
  size_t first_partial_block_bytes_count;
  size_t last_partial_block_bytes_count;
  size_t full_inclusive_blocks_bytes_count;
  offset_translator_->ReduceLogicalRangeToFullLogicalBlocks(
      logical_offset, count, &first_partial_block_bytes_count,
      &last_partial_block_bytes_count, &full_inclusive_blocks_bytes_count);

  // Bounce block for writing the first partial block in the range, if any.
  Block first_block;
  if (first_partial_block_bytes_count > 0) {
    if (!ReadFullBlock(
            *file_ctrl,
            logical_offset + first_partial_block_bytes_count - kBlockLength,
            &first_block)) {
      LOG(ERROR)
          << "failed to read the first misaligned block when writing, fd = "
          << fd;
      return -1;
    }

    std::copy_n(
        reinterpret_cast<const uint8_t *>(buf), first_partial_block_bytes_count,
        first_block.data() + kBlockLength - first_partial_block_bytes_count);
  }

  // Bounce block for writing the last partial block in the range, if any.
  Block last_block;
  if (last_partial_block_bytes_count > 0) {
    if (!ReadFullBlock(*file_ctrl,
                       logical_offset + count - last_partial_block_bytes_count,
                       &last_block)) {
      LOG(ERROR)
          << "failed to read the last misaligned block when writing, fd = "
          << fd;
      return -1;
    }

    std::copy_n(reinterpret_cast<const uint8_t *>(buf) + count -
                    last_partial_block_bytes_count,
                last_partial_block_bytes_count, last_block.data());
  }

  const off_t first_logical_block_offset =
      (first_partial_block_bytes_count > 0)
          ? (logical_offset + first_partial_block_bytes_count - kBlockLength)
          : logical_offset;
  const off_t first_physical_block_offset =
      offset_translator_->LogicalToPhysical(first_logical_block_offset);
  const int64_t eof_block_index = file_ctrl->ad->LeafCount();
  int64_t start_block_to_write = 0;
  if (first_physical_block_offset > file_ctrl->physical_size()) {
    // Append leafs to the Merkle Tree to account for sparse region blocks.
    int64_t sparse_blocks_count =
        (first_physical_block_offset - file_ctrl->physical_size()) /
        kSecureBlockLength;
    for (int64_t idx = 0; idx < sparse_blocks_count; idx++) {
      VLOG(2) << "Adding an empty auth tag to AD for a block "
                 "from a sparse region: "
              << absl::BytesToHexString(file_ctrl->zero_hash);
      file_ctrl->ad->AddLeafHash(file_ctrl->zero_hash);
    }
    start_block_to_write = eof_block_index + sparse_blocks_count;
  } else {
    int64_t blocks_to_eof =
        (file_ctrl->physical_size() - first_physical_block_offset) /
        kSecureBlockLength;
    start_block_to_write = eof_block_index - blocks_to_eof;
  }

  GcmCryptor *cryptor = GetGcmCryptor(*file_ctrl);
  if (!cryptor) {
    return -1;
  }

  VLOG(2) << "Writing data to file, count = " << count << ", fd = " << fd;

  // Use single write buffer to minimize the number of write calls to the host.
  std::vector<uint8_t> buffer;
  const int64_t blocks_to_write =
      full_inclusive_blocks_bytes_count / kBlockLength;
  const size_t physical_bytes_count = blocks_to_write * kSecureBlockLength;
  buffer.resize(physical_bytes_count);

  // Cycle through blocks.
  std::vector<Tag> tags;
  for (int64_t block_index = 0; block_index < blocks_to_write; block_index++) {
    const uint8_t *plaintext_data =
        GetPlaintextBuffer(first_partial_block_bytes_count, block_index, buf);

    // Source for encryption - bounce block or the supplied buffer.
    const uint8_t *encrypt_source;
    // Determine the source depending on whether the written block is at the end
    // of the full range.
    if (block_index == 0 && first_partial_block_bytes_count > 0) {
      encrypt_source = first_block.data();
    } else if (block_index == blocks_to_write - 1 &&
               last_partial_block_bytes_count > 0) {
      encrypt_source = last_block.data();
    } else {
      encrypt_source = plaintext_data;
    }

    Ciphertext *ciphertext =
        Ciphertext::Place(&buffer, block_index * kSecureBlockLength);
    Token *token = Token::Place(
        &buffer, block_index * kSecureBlockLength + kCipherBlockLength);

    // Encrypt the block.
    if (!cryptor->EncryptBlock(encrypt_source, token->data(),
                               ciphertext->data())) {
      LOG(ERROR) << "Encryption failed, fd = " << fd;
      return -1;
    }
    VLOG(2) << "Ciphertext generated: "
            << absl::BytesToHexString(absl::string_view(
                   reinterpret_cast<const char *>(ciphertext->data()),
                   kBlockLength));
    VLOG(2) << "Token generated: "
            << absl::BytesToHexString(absl::string_view(
                   reinterpret_cast<const char *>(token->data()),
                   kTokenLength));

    TagView tag(ciphertext->data() + kBlockLength, kTagLength);
    tags.push_back(tag);
    VLOG(2) << "Auth tag generated: "
            << absl::BytesToHexString(absl::string_view(
                   reinterpret_cast<const char *>(tag.data()), kTagLength));
  }

  // Move cursor to the first full block to write.
  if (first_partial_block_bytes_count > 0) {
    off_t offset =
        enc_untrusted_lseek(fd, first_physical_block_offset, SEEK_SET);
    if (offset == -1) {
      LOG(ERROR)
          << "Failed lseek to the fist block offset when writing file data.";
      return -1;
    }
  }

  // Note: with block alignment constraint in place, partial block writes are
  // not permissible - complete blocks must be written. Thus, the options are:
  // 1. Allow partial yet block-aligned writes - this would require truncating
  //    partially written blocks, which has a perf impact.
  // 2. Require complete data to be written in a write loop that terminates only
  //    on error or when all data has been written, following the POSIX model -
  //    this may lead to "long" writes when "large" amount of data is written.
  // In this code optimize operation for full writes - i.e. the option #2.
  ssize_t bytes_written = write_all(fd, buffer.data(), physical_bytes_count);
  if (bytes_written != physical_bytes_count) {
    LOG(ERROR) << "Failed to write encrypted data to file, path="
               << file_ctrl->path << ", bytes written = " << bytes_written;
    return -1;
  }

  // Move cursor to the position of the end of the write range.
  if (last_partial_block_bytes_count > 0) {
    off_t new_cur_logical_offset = logical_offset + count;
    off_t new_cur_physical_offset =
        offset_translator_->LogicalToPhysical(new_cur_logical_offset);
    off_t offset = enc_untrusted_lseek(fd, new_cur_physical_offset, SEEK_SET);
    if (offset == -1) {
      LOG(ERROR)
          << "Failed lseek to the last block offset when reading file data.";
      return -1;
    }
  }

  for (int64_t idx = 0; idx < tags.size(); idx++) {
    std::string tag_string(reinterpret_cast<char *>(tags[idx].data()),
                           kTagLength);
    int64_t block_index = start_block_to_write + idx;
    if (block_index < eof_block_index) {
      VLOG(2) << "Updating auth tag on AD: "
              << absl::BytesToHexString(tag_string);
      file_ctrl->ad->UpdateLeaf(block_index + 1, tag_string);
    } else {
      VLOG(2) << "Appending auth tag to AD: "
              << absl::BytesToHexString(tag_string);
      file_ctrl->ad->AddLeaf(tag_string);
    }
  }

  file_ctrl->logical_size = logical_offset + count;

  if (!UpdateDigest(file_ctrl.get(), *cryptor)) {
    return -1;
  }

  VLOG(2) << "Wrote data to file, bytes_written = " << bytes_written;

  return count;
}

bool AeadHandler::FinalizeFile(int fd) {
  absl::MutexLock global_lock(&mu_);

  if (fd < 0) {
    errno = EINVAL;
    return false;
  }

  auto entry = fmap_.find(fd);
  if (entry == fmap_.end()) {
    LOG(ERROR) << "Attempt made to finalize uninitialized file, fd = " << fd;
    errno = ENOENT;
    return false;
  }

  // Do not need to wait until the file is no longer operated on - shared_ptr
  // taken by the operator will keep file_ctrl alive and allow it to take and
  // release the lock on its own schedule. Removal from the maps here will not
  // impact that ability.

  VLOG(2) << "Finalizing secure file, fd = " << fd
          << ", pathname = " << entry->second->path;
  opened_files_.erase(entry->second->path);
  fmap_.erase(entry);

  return true;
}

// Note: questionable whether to allow setting the key only on newly opened
// files, and only if not set yet - arguably, such intelligence may need to
// reside outside of AeadHandler on the side of the IOCTL client. If not done
// correctly by the client, IO ops will simply fail, as intended.
int AeadHandler::SetMasterKey(int fd, const uint8_t *key_data,
                              uint32_t key_length) {
  if (!key_data || key_length != kKeyLength) {
    LOG(ERROR) << "Attempt made to set an invalid key.";
    errno = EINVAL;
    return -1;
  }

  std::shared_ptr<FileControl> file_ctrl;
  {
    absl::MutexLock global_lock(&mu_);

    auto entry = fmap_.find(fd);
    if (entry == fmap_.end()) {
      LOG(ERROR) << "Attempt made to set key on an unopened file, fd = " << fd;
      errno = ENOENT;
      return -1;
    }

    file_ctrl = entry->second;
  }

  absl::MutexLock lock(&file_ctrl->mu);

  if (file_ctrl->is_deserialized) {
    if (memcmp(file_ctrl->master_key->data(), key_data, kKeyLength) != 0) {
      LOG(ERROR) << "Attempt made to set a new key on an existing file, fd="
                 << fd;
      return -1;
    }

    return 0;
  }

  file_ctrl->master_key =
      absl::make_unique<GcmCryptorKey>(key_data, key_length);
  if (!Deserialize(file_ctrl.get())) {
    LOG(ERROR) << "Failed to deserialize integrity metadata for file, path="
               << file_ctrl->path;
    return -1;
  }

  file_ctrl->is_deserialized = true;
  return 0;
}

const OffsetTranslator &AeadHandler::GetOffsetTranslator() const {
  return *offset_translator_;
}

off_t AeadHandler::GetLogicalFileSize(int fd) {
  absl::MutexLock global_lock(&mu_);
  auto entry = fmap_.find(fd);
  if (entry == fmap_.end()) {
    LOG(ERROR)
        << "Attempt made to get logical file size on an unopened file, fd = "
        << fd;
    return -1;
  }
  return entry->second->logical_size;
}

}  // namespace storage
}  // namespace platform
}  // namespace asylo
