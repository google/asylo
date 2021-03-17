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

// Test suite for the Secure IO Library.

// IO syscall interface constants.
#include "asylo/platform/storage/secure/enclave_storage_secure.h"

#include <fcntl.h>
#include <openssl/rand.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/util/logging.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/storage/secure/aead_handler.h"
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/test/util/test_flags.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"

namespace asylo {
namespace {

using platform::crypto::gcmlib::kKeyLength;
using platform::storage::AeadHandler;
using platform::storage::kBlockLength;
using platform::storage::kCipherBlockLength;
using platform::storage::kFileHashLength;
using platform::storage::secure_close;
using platform::storage::secure_fstat;
using platform::storage::secure_lseek;
using platform::storage::secure_open;
using platform::storage::secure_read;
using platform::storage::secure_write;
using ::testing::Not;

constexpr size_t kMaxTestBufLen = 1000;
constexpr char kTamperData[] = "Exceedingly rare string";

class EnclaveStorageSecureTest : public ::testing::Test,
                                 public ::testing::WithParamInterface<size_t> {
 protected:
  void SetUp() override { PrepareTest(); }
  void PrepareTest();
  Status OpenWriteClose(off_t offset);
  Status OpenReadVerifyClose(off_t offset, size_t bytes_expected);

  const int64_t kFileHeaderLength = kFileHashLength + sizeof(size_t);
  const std::string &GetPath() const { return path_; }
  const void *GetWriteBuffer() const {
    return reinterpret_cast<const void *>(write_buffer_);
  }
  void *GetReadBuffer() { return reinterpret_cast<void *>(read_buffer_); }
  const void *GetZeroBuffer() const {
    return reinterpret_cast<const void *>(zero_buffer_);
  }
  int EmulateSetKeyIoctl(int fd) const {
    return AeadHandler::GetInstance().SetMasterKey(fd, key_.data(),
                                                   key_.size());
  }

  size_t test_buf_len_;
  std::string path_;
  CleansingVector<uint8_t> key_;
  char write_buffer_[kMaxTestBufLen];
  char read_buffer_[kMaxTestBufLen];
  char zero_buffer_[kMaxTestBufLen];
};

const size_t buffer_length_vals[] = {128, 160, 512, 544};

INSTANTIATE_TEST_SUITE_P(Instance1, EnclaveStorageSecureTest,
                         ::testing::ValuesIn(buffer_length_vals));

void EnclaveStorageSecureTest::PrepareTest() {
  path_ = absl::StrCat(absl::GetFlag(FLAGS_test_tmpdir),
                       "/EnclaveStorageSecureTest.txt");

  // Note: this step should not be required, but the observation is that
  // occasionally the test is executed on the same (virtual) machine.
  LOG(INFO) << "Cleaning up test file if present, path = " << path_;
  remove(path_.c_str());

  // Generate the test key.
  key_.resize(kKeyLength);
  ASSERT_EQ(RAND_bytes(key_.data(), key_.size()), 1);

  // Prepare test buffer.
  test_buf_len_ = GetParam();
  constexpr size_t pattern_length = 16;
  ASSERT_LE(test_buf_len_, kMaxTestBufLen);
  ASSERT_EQ(test_buf_len_ % pattern_length, 0);

  constexpr char pattern[pattern_length + 1] = "qwerasdfzxcv1234";
  for (int scan = 0; scan < kMaxTestBufLen / pattern_length; scan++) {
    memcpy(write_buffer_ + scan * pattern_length, pattern, pattern_length);
  }
  memset(zero_buffer_, 0, kMaxTestBufLen);
}

Status EnclaveStorageSecureTest::OpenWriteClose(off_t offset) {
  // Open for write.
  int fd = secure_open(GetPath().c_str(), O_WRONLY | O_CREAT,
                       S_IRWXU | S_IRWXG | S_IRWXO);
  LOG(INFO) << "Opened file for write, fd = " << fd;
  if (fd < 0) {
    return absl::InternalError(
        absl::StrCat("Secure open path ", GetPath(), " failed."));
  }

  platform::storage::FdCloser fd_closer(fd, &secure_close);

  if (EmulateSetKeyIoctl(fd) != 0) {
    return absl::InternalError("Set Master Key failed.");
  }

  if (offset > 0) {
    if (secure_lseek(fd, offset, SEEK_SET) != offset) {
      return absl::InternalError("Secure lseek failed.");
    }
    LOG(INFO) << "Performed lseek to offset = " << offset;
  }

  // Write.
  if (secure_write(fd, GetWriteBuffer(), test_buf_len_) != test_buf_len_) {
    return absl::InternalError("Secure write failed.");
  }

  fd_closer.release();  // Make no more attempts to close before return.

  // Close.
  if (secure_close(fd) != 0) {
    return absl::InternalError("Secure close failed.");
  }

  // Cannot close twice.
  if (secure_close(fd) != -1) {
    return absl::InternalError(
        "Secure close the same fd a second time succeeded.");
  }

  return absl::OkStatus();
}

Status EnclaveStorageSecureTest::OpenReadVerifyClose(off_t offset,
                                                     size_t bytes_expected) {
  // Open for read.
  int fd = secure_open(GetPath().c_str(), O_RDONLY);
  LOG(INFO) << "Opened file for read, fd = " << fd;
  if (fd < 0) {
    return absl::InternalError(
        absl::StrCat("Secure open path ", GetPath(), " failed."));
  }

  platform::storage::FdCloser fd_closer(fd, &secure_close);

  if (EmulateSetKeyIoctl(fd) != 0) {
    return absl::InternalError("Set master Key failed.");
  }

  if (offset > 0) {
    if (secure_lseek(fd, offset, SEEK_SET) != offset) {
      return absl::InternalError("Secure lseek failed.");
    }
    LOG(INFO) << "Performed lseek to offset = " << offset;
  }

  // Read.
  if (secure_read(fd, GetReadBuffer(), test_buf_len_) != bytes_expected) {
    return absl::InternalError("Secure read failed.");
  }

  // Verify.
  if (memcmp(GetWriteBuffer(), GetReadBuffer(), bytes_expected) != 0) {
    return absl::InternalError("Bytes read different from bytes written.");
  }

  fd_closer.release();  // Make no more attempts to close before return.

  // Close.
  if (secure_close(fd) != 0) {
    return absl::InternalError("secure close failed.");
  }

  // Cannot close twice.
  if (secure_close(fd) != -1) {
    return absl::InternalError(
        "Secure close the same fd a second time succeeded.");
  }

  return absl::OkStatus();
}

//
// Success cases.
//

TEST_P(EnclaveStorageSecureTest, ReadWriteSuccess) {
  EXPECT_THAT(OpenWriteClose(0), IsOk());
  EXPECT_THAT(OpenReadVerifyClose(0, test_buf_len_), IsOk());
}

TEST_P(EnclaveStorageSecureTest, ReadWriteInterlacedSuccess) {
  const int iterations = 10;
  for (int iter = 0; iter < iterations; iter++) {
    // Open for read/write.
    int fd = secure_open(GetPath().c_str(), O_RDWR | O_CREAT,
                         S_IRWXU | S_IRWXG | S_IRWXO);
    LOG(INFO) << "Opened file for read and write, fd = " << fd;
    ASSERT_GE(fd, 0);

    ASSERT_EQ(EmulateSetKeyIoctl(fd), 0);

    for (int scan = 0; scan < iter; scan++) {
      // Read to the EOF.
      EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
      EXPECT_EQ(memcmp(GetWriteBuffer(), GetReadBuffer(), test_buf_len_), 0);
      LOG(INFO) << "Read chunk of file, iter = " << iter << ", scan = " << scan;
    }

    // Write.
    EXPECT_EQ(secure_write(fd, GetWriteBuffer(), test_buf_len_), test_buf_len_);

    // Close.
    EXPECT_EQ(secure_close(fd), 0);
  }
}

TEST_P(EnclaveStorageSecureTest, LseekReadWriteInterlacedSingleFdSuccess) {
  const int interations = 10;
  for (int iter = 0; iter < interations; iter++) {
    // Open for read/write.
    int fd = secure_open(GetPath().c_str(), O_RDWR | O_CREAT,
                         S_IRWXU | S_IRWXG | S_IRWXO);
    LOG(INFO) << "Opened file for read and write, fd = " << fd;
    ASSERT_GE(fd, 0);

    EXPECT_EQ(EmulateSetKeyIoctl(fd), 0);

    if (iter > 0) {
      // Lseek to last but one block.
      off_t offset = (iter - 1) * test_buf_len_;
      EXPECT_EQ(secure_lseek(fd, offset, SEEK_SET), offset);
      LOG(INFO) << "Performed lseek to offset = " << offset;

      // Read.
      EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
      EXPECT_EQ(memcmp(GetWriteBuffer(), GetReadBuffer(), test_buf_len_), 0);
      LOG(INFO) << "Read chunk of file after lseek, iter = " << iter;
    }

    // Write.
    EXPECT_EQ(secure_write(fd, GetWriteBuffer(), test_buf_len_), test_buf_len_);

    // Close.
    EXPECT_EQ(secure_close(fd), 0);
  }
}

TEST_P(EnclaveStorageSecureTest, LseekReadWriteInterlacedMultiFdSuccess) {
  const int interations = 10;
  std::vector<int> fds;
  for (int iter = 0; iter < interations; iter++) {
    // Open for read/write.
    int fd = secure_open(GetPath().c_str(), O_RDWR | O_CREAT,
                         S_IRWXU | S_IRWXG | S_IRWXO);
    LOG(INFO) << "Opened file for read and write, fd = " << fd;
    ASSERT_GE(fd, 0);

    EXPECT_EQ(EmulateSetKeyIoctl(fd), 0);

    if (iter > 0) {
      // Lseek to last but one block.
      off_t offset = (iter - 1) * test_buf_len_;
      EXPECT_EQ(secure_lseek(fd, offset, SEEK_SET), offset);
      LOG(INFO) << "Performed lseek to offset = " << offset;

      // Read.
      EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
      EXPECT_EQ(memcmp(GetWriteBuffer(), GetReadBuffer(), test_buf_len_), 0);
      LOG(INFO) << "Read chunk of file after lseek, iter = " << iter;
    }

    // Write.
    EXPECT_EQ(secure_write(fd, GetWriteBuffer(), test_buf_len_), test_buf_len_);

    // Prepare to close.
    fds.push_back(fd);
  }

  for (const int &fd : fds) {
    EXPECT_EQ(secure_close(fd), 0);
  }
}

TEST_P(EnclaveStorageSecureTest, ReopenReadWriteSuccess) {
  // Open for write.
  int fd = secure_open(GetPath().c_str(), O_WRONLY | O_CREAT,
                       S_IRWXU | S_IRWXG | S_IRWXO);
  LOG(INFO) << "Opened file for write, fd = " << fd;
  ASSERT_GE(fd, 0);

  EXPECT_EQ(EmulateSetKeyIoctl(fd), 0);

  // Close.
  EXPECT_EQ(secure_close(fd), 0);

  EXPECT_THAT(OpenWriteClose(0), IsOk());
  EXPECT_THAT(OpenReadVerifyClose(0, test_buf_len_), IsOk());
}

TEST_P(EnclaveStorageSecureTest, RedundantIoctlSuccess) {
  // Open for write.
  int fd = secure_open(GetPath().c_str(), O_WRONLY | O_CREAT,
                       S_IRWXU | S_IRWXG | S_IRWXO);
  LOG(INFO) << "Opened file for write, fd = " << fd;
  EXPECT_GE(fd, 0);

  EXPECT_EQ(EmulateSetKeyIoctl(fd), 0);

  EXPECT_EQ(EmulateSetKeyIoctl(fd), 0);

  // Close.
  EXPECT_EQ(secure_close(fd), 0);
}

TEST_P(EnclaveStorageSecureTest, ReadWriteWithSparseSuccessTest) {
  for (bool sparse_head : {false, true}) {
    PrepareTest();
    off_t head_offset = 0;
    if (sparse_head) {
      // Create sparse buffer at the head of the file.
      head_offset = test_buf_len_;
    }

    EXPECT_THAT(OpenWriteClose(head_offset), IsOk());

    // Create a sparse region beyond EOF - lseek to 3rd buffer.
    off_t offset = head_offset + 2 * test_buf_len_;

    EXPECT_THAT(OpenWriteClose(offset), IsOk());

    // Open for read.
    int fd = secure_open(GetPath().c_str(), O_RDONLY);
    LOG(INFO) << "Opened file for read, fd = " << fd;
    ASSERT_GE(fd, 0);

    EXPECT_EQ(EmulateSetKeyIoctl(fd), 0);

    if (sparse_head) {
      // Read the sparse head buffer.
      EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
      EXPECT_EQ(memcmp(GetZeroBuffer(), GetReadBuffer(), test_buf_len_), 0);
    }

    // Read 1st buffer with data.
    EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
    EXPECT_EQ(memcmp(GetWriteBuffer(), GetReadBuffer(), test_buf_len_), 0);

    // Read 2nd buffer nullified.
    EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
    EXPECT_EQ(memcmp(GetZeroBuffer(), GetReadBuffer(), test_buf_len_), 0);

    // Read 3rd buffer with data.
    EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
    EXPECT_EQ(memcmp(GetWriteBuffer(), GetReadBuffer(), test_buf_len_), 0);

    // Close.
    EXPECT_EQ(secure_close(fd), 0);

    // Create a sparse region beyond EOF - lseek to 5th buffer.
    offset = head_offset + 4 * test_buf_len_;
    EXPECT_THAT(OpenWriteClose(offset), IsOk());

    // Open for read.
    fd = secure_open(GetPath().c_str(), O_RDONLY);
    LOG(INFO) << "Opened file for read, fd = " << fd;
    ASSERT_GE(fd, 0);

    EXPECT_EQ(EmulateSetKeyIoctl(fd), 0);

    if (sparse_head) {
      // Read the sparse head buffer.
      EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
      EXPECT_EQ(memcmp(GetZeroBuffer(), GetReadBuffer(), test_buf_len_), 0);
    }

    // Read 1st buffer with data.
    EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
    EXPECT_EQ(memcmp(GetWriteBuffer(), GetReadBuffer(), test_buf_len_), 0);

    // Read 2nd buffer nullified.
    EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
    EXPECT_EQ(memcmp(GetZeroBuffer(), GetReadBuffer(), test_buf_len_), 0);

    // Read 3rd buffer with data.
    EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
    EXPECT_EQ(memcmp(GetWriteBuffer(), GetReadBuffer(), test_buf_len_), 0);

    // Read 4th buffer nullified.
    EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
    EXPECT_EQ(memcmp(GetZeroBuffer(), GetReadBuffer(), test_buf_len_), 0);

    // Read 5th buffer with data.
    EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
    EXPECT_EQ(memcmp(GetWriteBuffer(), GetReadBuffer(), test_buf_len_), 0);

    // Close.
    EXPECT_EQ(secure_close(fd), 0);
  }
}

TEST_P(EnclaveStorageSecureTest, ModificationWriteSuccessTest) {
  EXPECT_THAT(OpenWriteClose(0), IsOk());
  EXPECT_THAT(OpenReadVerifyClose(0, test_buf_len_), IsOk());

  // Test update-only write.
  EXPECT_THAT(OpenWriteClose(0), IsOk());
  EXPECT_THAT(OpenReadVerifyClose(0, test_buf_len_), IsOk());

  if (test_buf_len_ / kBlockLength != 1) {
    // Test mixed update-append write: lseek to the middle of written range -
    // the next write will include both updated and appended file data.
    off_t offset = test_buf_len_ / 2;

    EXPECT_THAT(OpenWriteClose(offset), IsOk());

    // Open for read.
    int fd = secure_open(GetPath().c_str(), O_RDONLY);
    LOG(INFO) << "Opened file for read, fd = " << fd;
    EXPECT_GE(fd, 0);

    EXPECT_EQ(EmulateSetKeyIoctl(fd), 0);

    // Read 1/2 of the test buffer - read data written before the last write.
    EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_ / 2),
              test_buf_len_ / 2);
    EXPECT_EQ(memcmp(GetWriteBuffer(), GetReadBuffer(), test_buf_len_ / 2), 0);

    // Read 1 full test buffer - read data written in the last write, 1/2 of the
    // buffer was an update, and 1/2 - append.
    EXPECT_EQ(secure_read(fd, GetReadBuffer(), test_buf_len_), test_buf_len_);
    EXPECT_EQ(memcmp(GetWriteBuffer(), GetReadBuffer(), test_buf_len_), 0);

    // Close.
    EXPECT_EQ(secure_close(fd), 0);
  }
}

TEST_P(EnclaveStorageSecureTest, SimpleMisalignedWriteSuccess) {
  EXPECT_THAT(OpenWriteClose(0), IsOk());
  // Lseek to the middle of the last block.
  off_t offset = test_buf_len_ - kBlockLength / 2;
  EXPECT_THAT(OpenWriteClose(offset), IsOk());
}

TEST_P(EnclaveStorageSecureTest, SimpleMisalignedReadSuccess) {
  EXPECT_THAT(OpenWriteClose(0), IsOk());
  // Lseek to the middle of the first block.
  off_t offset = kBlockLength / 2;
  EXPECT_THAT(OpenReadVerifyClose(offset, test_buf_len_ - offset), IsOk());
}

TEST_P(EnclaveStorageSecureTest, StatReturnLogicalFileSizeSuccess) {
  EXPECT_THAT(OpenWriteClose(0), IsOk());
  int fd = secure_open(GetPath().c_str(), O_RDONLY);
  ASSERT_GE(fd, 0);
  ASSERT_EQ(EmulateSetKeyIoctl(fd), 0);
  struct stat file_stat;
  EXPECT_EQ(secure_fstat(fd, &file_stat), 0);
  EXPECT_EQ(file_stat.st_size, test_buf_len_);
  EXPECT_EQ(secure_close(fd), 0);
}

TEST_P(EnclaveStorageSecureTest, LseekEndSuccess) {
  EXPECT_THAT(OpenWriteClose(0), IsOk());
  int fd = secure_open(GetPath().c_str(), O_RDONLY);
  ASSERT_GE(fd, 0);
  ASSERT_EQ(EmulateSetKeyIoctl(fd), 0);
  off_t offset = secure_lseek(fd, 0, SEEK_END);
  EXPECT_EQ(offset, test_buf_len_);
  EXPECT_EQ(secure_close(fd), 0);
}

//
// Failure cases.
//

TEST_P(EnclaveStorageSecureTest, ReadWriteDataModified) {
  EXPECT_THAT(OpenWriteClose(0), IsOk());
  // Modify file data - form of tampering.
  int fd = enc_untrusted_open(GetPath().c_str(), O_WRONLY);
  EXPECT_GE(fd, 0);
  EXPECT_GT(enc_untrusted_lseek(fd, kFileHeaderLength, SEEK_SET), 0);
  EXPECT_GT(enc_untrusted_write(fd, kTamperData, ABSL_ARRAYSIZE(kTamperData)),
            0);
  ASSERT_EQ(enc_untrusted_fsync(fd), 0) << strerror(errno);
  ASSERT_EQ(enc_untrusted_close(fd), 0) << strerror(errno);
  EXPECT_THAT(OpenReadVerifyClose(0, test_buf_len_),
              StatusIs(absl::StatusCode::kInternal, "Secure read failed."));
}

TEST_P(EnclaveStorageSecureTest, ReadWriteDigestModified) {
  EXPECT_THAT(OpenWriteClose(0), IsOk());
  // Modify file digest - form of tampering.
  int fd = enc_untrusted_open(GetPath().c_str(), O_WRONLY);
  EXPECT_GE(fd, 0);
  EXPECT_GT(enc_untrusted_write(fd, kTamperData, ABSL_ARRAYSIZE(kTamperData)),
            0);
  ASSERT_EQ(enc_untrusted_fsync(fd), 0) << strerror(errno);
  ASSERT_EQ(enc_untrusted_close(fd), 0) << strerror(errno);
  EXPECT_THAT(OpenReadVerifyClose(0, test_buf_len_),
              StatusIs(absl::StatusCode::kInternal, "Set master Key failed."));
}

TEST_P(EnclaveStorageSecureTest, ReadWriteAuthTagsModified) {
  EXPECT_THAT(OpenWriteClose(0), IsOk());

  // Modify an auth tag - form of tampering.
  int fd = enc_untrusted_open(GetPath().c_str(), O_WRONLY);
  ASSERT_GE(fd, 0);
  EXPECT_GT(enc_untrusted_lseek(fd, kFileHeaderLength + kBlockLength, SEEK_SET),
            0);
  EXPECT_GT(enc_untrusted_write(fd, kTamperData, ABSL_ARRAYSIZE(kTamperData)),
            0);
  ASSERT_EQ(enc_untrusted_fsync(fd), 0) << strerror(errno);
  ASSERT_EQ(enc_untrusted_close(fd), 0) << strerror(errno);
  EXPECT_THAT(OpenReadVerifyClose(0, test_buf_len_),
              StatusIs(absl::StatusCode::kInternal, "Set master Key failed."));
}

TEST_P(EnclaveStorageSecureTest, ReadWriteTokensModified) {
  EXPECT_THAT(OpenWriteClose(0), IsOk());

  // Modify a token - form of tampering.
  int fd = enc_untrusted_open(GetPath().c_str(), O_WRONLY);
  ASSERT_GE(fd, 0);
  EXPECT_GT(
      enc_untrusted_lseek(fd, kFileHeaderLength + kCipherBlockLength, SEEK_SET),
      0);
  EXPECT_GT(enc_untrusted_write(fd, kTamperData, ABSL_ARRAYSIZE(kTamperData)),
            0);
  ASSERT_EQ(enc_untrusted_fsync(fd), 0) << strerror(errno);
  ASSERT_EQ(enc_untrusted_close(fd), 0) << strerror(errno);
  EXPECT_THAT(OpenReadVerifyClose(0, test_buf_len_),
              StatusIs(absl::StatusCode::kInternal, "Secure read failed."));
}

TEST_P(EnclaveStorageSecureTest, FileTruncateAttack) {
  EXPECT_THAT(OpenWriteClose(0), IsOk());

  // Truncate the file - form of tampering.
  int fd = enc_untrusted_open(GetPath().c_str(), O_WRONLY | O_TRUNC);
  enc_untrusted_close(fd);
  EXPECT_THAT(OpenWriteClose(0),
              StatusIs(absl::StatusCode::kInternal, "Set Master Key failed."));
}

TEST_P(EnclaveStorageSecureTest, KeyNotSetFailure) {
  // Open for write.
  int fd = secure_open(GetPath().c_str(), O_WRONLY | O_CREAT,
                       S_IRWXU | S_IRWXG | S_IRWXO);
  LOG(INFO) << "Opened file for write, fd = " << fd;
  ASSERT_GE(fd, 0);

  // Write.
  EXPECT_EQ(secure_write(fd, GetWriteBuffer(), test_buf_len_), -1);

  // Close.
  EXPECT_EQ(secure_close(fd), 0);
}

TEST_P(EnclaveStorageSecureTest, RedundantIoctlFailure) {
  // Open for write.
  int fd = secure_open(GetPath().c_str(), O_WRONLY | O_CREAT,
                       S_IRWXU | S_IRWXG | S_IRWXO);
  LOG(INFO) << "Opened file for write, fd = " << fd;
  ASSERT_GE(fd, 0);

  EXPECT_EQ(EmulateSetKeyIoctl(fd), 0);
  EXPECT_EQ(RAND_bytes(key_.data(), key_.size()), 1);
  EXPECT_EQ(EmulateSetKeyIoctl(fd), -1);

  // Close.
  EXPECT_EQ(secure_close(fd), 0);
}

TEST_P(EnclaveStorageSecureTest, UnknownFdIoctlFailure) {
  // Open for write.
  int fd = secure_open(GetPath().c_str(), O_WRONLY | O_CREAT,
                       S_IRWXU | S_IRWXG | S_IRWXO);
  LOG(INFO) << "Opened file for write, fd = " << fd;
  ASSERT_GE(fd, 0);

  // Close.
  EXPECT_EQ(secure_close(fd), 0);
  EXPECT_EQ(EmulateSetKeyIoctl(fd), -1);
  EXPECT_EQ(errno, ENOENT);
}

TEST_P(EnclaveStorageSecureTest, UnsupportedFileCreationFlagFailure) {
  // Open for write with O_APPEND.
  int fd = secure_open(GetPath().c_str(), O_WRONLY | O_CREAT | O_APPEND,
                       S_IRWXU | S_IRWXG | S_IRWXO);
  EXPECT_EQ(fd, -1);

  // Open for write with O_TRUNC.
  fd = secure_open(GetPath().c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRWXU | S_IRWXG | S_IRWXO);
  EXPECT_EQ(fd, -1);
}

}  // namespace
}  // namespace asylo
