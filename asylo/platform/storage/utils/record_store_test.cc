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


#include <cstddef>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/platform/storage/utils/record_store.h"
#include "asylo/platform/storage/utils/test_utils.h"
#include "asylo/platform/storage/utils/untrusted_file.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

// Ensure that reading and writing records through a RecordStore returns the
// expected values.
TEST(RecordStoreTest, WriteRead) {
  int fd = CreateEmptyTempFileOrDie("write_read.tmp");
  platform::storage::FdCloser closer(fd);
  UntrustedFile file(fd);

  constexpr size_t kCapacity = 16;
  constexpr size_t kRecordCount = 256;
  RecordStore<size_t> records(kCapacity, &file);

  for (size_t i = 0; i < kRecordCount; i++) {
    size_t record;
    off_t offset = i * sizeof(size_t);
    ASYLO_EXPECT_OK(records.Write(offset, i));
    ASYLO_EXPECT_OK(records.Read(offset, &record));
    EXPECT_EQ(record, i);
  }

  for (size_t i = 0; i < kRecordCount; i++) {
    size_t record;
    off_t offset = i * sizeof(size_t);
    ASYLO_EXPECT_OK(records.Read(offset, &record));
    EXPECT_EQ(record, i);
  }
}

// Ensure that records items are evicted in LRU order.
TEST(RecordStoreTest, Eviction) {
  int fd = CreateEmptyTempFileOrDie("eviction.tmp");
  platform::storage::FdCloser closer(fd);
  UntrustedFile file(fd);

  constexpr size_t kCapacity = 16;
  constexpr size_t kRecordCount = 256;

  RecordStore<size_t> write_store(kCapacity, &file);
  for (size_t i = 0; i < kRecordCount; i++) {
    off_t offset = i * sizeof(size_t);
    ASYLO_EXPECT_OK(write_store.Write(offset, i));
    size_t first_cached = i >= kCapacity ? i - kCapacity + 1 : 0;
    size_t last_cached = i;
    for (size_t j = 0; j < kRecordCount; j++) {
      EXPECT_EQ(write_store.IsCached(j * sizeof(size_t)),
                j >= first_cached && j <= last_cached);
    }
  }
  ASYLO_ASSERT_OK(write_store.Flush());

  RecordStore<size_t> read_store(kCapacity, &file);
  for (size_t i = 0; i < kRecordCount; i++) {
    off_t offset = i * sizeof(size_t);
    size_t record;
    ASYLO_EXPECT_OK(read_store.Read(offset, &record));
    EXPECT_TRUE(read_store.IsCached(offset));
    size_t first_cached = i >= kCapacity ? i - kCapacity + 1 : 0;
    size_t last_cached = i;
    for (size_t j = 0; j < kRecordCount; j++) {
      EXPECT_EQ(read_store.IsCached(j * sizeof(size_t)),
                j >= first_cached && j <= last_cached);
    }
  }
}

// Ensure that cached writes are flushed when a RecordStore goes out of scope.
TEST(RecordStoreTest, Flush) {
  int fd = CreateEmptyTempFileOrDie("flush.tmp");
  platform::storage::FdCloser closer(fd);
  UntrustedFile file(fd);

  constexpr size_t kCapacity = 256;
  constexpr size_t kRecordCount = 256;

  {
    RecordStore<size_t> records(kCapacity, &file);
    for (size_t i = 0; i < kRecordCount; i++) {
      off_t offset = i * sizeof(size_t);
      ASYLO_EXPECT_OK(records.Write(offset, i));
    }
  }

  EXPECT_THAT(file.Size(), IsOkAndHolds(kRecordCount * sizeof(size_t)));
  for (size_t i = 0; i < kRecordCount; i++) {
    size_t record;
    ASYLO_EXPECT_OK(file.Read(&record, i * sizeof(size_t), sizeof(size_t)));
    EXPECT_EQ(record, i);
  }
}

}  // namespace
}  // namespace asylo
