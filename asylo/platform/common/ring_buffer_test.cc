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

#include "asylo/platform/common/ring_buffer.h"

#include <cstdint>
#include <cstdlib>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

namespace asylo {

constexpr const size_t kDataSize = 4 * 1024 * 1024;

// Exposes NonBlockingWrite and NonBlockingRead for testing.
template <size_t Capacity>
class RingBufferForTest : public RingBuffer<Capacity> {
 public:
  size_t NonBlockingWrite(const uint8_t *buf, size_t nbyte) {
    return RingBuffer<Capacity>::NonBlockingWrite(buf, nbyte);
  }

  size_t NonBlockingRead(uint8_t *buf, size_t nbyte) {
    return RingBuffer<Capacity>::NonBlockingRead(buf, nbyte);
  }
};

// Generate a series of test data.
std::vector<uint8_t> MakeTestData(size_t size) {
  uint8_t f1 = 0;
  uint8_t f2 = 1;
  std::vector<uint8_t> data(size);
  for (int i = 0; i < size; i++) {
    uint8_t next = f1 + f2;
    data[i] = next;
    f1 = f2;
    f2 = next;
  }
  return data;
}

class RingBufferTest : public ::testing::Test {
 protected:
  void SetUp() final {
    srandom(::testing::UnitTest::GetInstance()->random_seed());
    scratch_ = std::vector<uint8_t>(kDataSize, 0);
    data_ = MakeTestData(kDataSize);
  }

  void ReadTestData(std::vector<uint8_t> *out) {
    size_t read_count = 0;
    constexpr size_t kReadSize = 4096;
    while (!(buf_.empty() && buf_.is_closed_for_write())) {
      uint8_t read_buffer[kReadSize];
      size_t sz = buf_.Read(read_buffer, kReadSize);
      out->resize(read_count + sz);
      memcpy(out->data() + read_count, read_buffer, sz);
      read_count += sz;
    }
    buf_.close_for_read();
  }

  void WriteTestData() {
    buf_.Write(data_.data(), kDataSize);
    buf_.close_for_write();
  }

  RingBufferForTest<kDataSize> buf_;
  std::vector<uint8_t> scratch_;
  std::vector<uint8_t> data_;
};

TEST_F(RingBufferTest, BasicProperties) {
  ASSERT_EQ(buf_.capacity(), kDataSize);
  EXPECT_EQ(buf_.size(), 0);
  EXPECT_TRUE(buf_.empty());
  size_t rc = buf_.NonBlockingWrite(data_.data(), buf_.capacity());
  EXPECT_EQ(rc, buf_.capacity());
  EXPECT_TRUE(buf_.full());
  size_t size = buf_.size();
  EXPECT_EQ(buf_.size(), kDataSize);
  rc = buf_.NonBlockingRead(scratch_.data(), size);
  EXPECT_EQ(rc, buf_.capacity());
  EXPECT_EQ(memcmp(data_.data(), scratch_.data(), size), 0);
  EXPECT_TRUE(buf_.empty());
}

TEST_F(RingBufferTest, VersionMatching) {
  using Tiny = RingBuffer<2>;
  using Medium = RingBuffer<32>;
  using Big = RingBuffer<64>;

  Tiny tiny;
  Medium medium;
  Big big;

  EXPECT_EQ(tiny.InstanceVersion(), Tiny::TypeVersion());
  EXPECT_EQ(medium.InstanceVersion(), Medium::TypeVersion());
  EXPECT_EQ(big.InstanceVersion(), Big::TypeVersion());
  EXPECT_NE(tiny.InstanceVersion(), Medium::TypeVersion());
  EXPECT_NE(medium.InstanceVersion(), Big::TypeVersion());
  EXPECT_NE(big.InstanceVersion(), Tiny::TypeVersion());
}

// Issue a long sequence of random reads and writes until we've moved a large
// chunk of data.
TEST_F(RingBufferTest, SingleThreadedStressTest) {
  std::vector<uint8_t> copied_data(kDataSize);
  const size_t kBiggestChunk = 1024;
  RingBufferForTest<255> small_buf;

  // Index into data_ to write to the buffer.
  int data_index = 0;
  // Index into the copied_data read from the buffer.
  int copy_index = 0;
  while (copy_index < kDataSize) {
    size_t next_chunk_size = random() % kBiggestChunk;
    switch (random() % 2) {
      // Write some bytes.
      case 0: {
        // Avoid writing past the end of data_.
        next_chunk_size = std::min(next_chunk_size, data_.size() - data_index);
        size_t count = std::min(next_chunk_size, small_buf.available());
        data_index +=
            small_buf.NonBlockingWrite(data_.data() + data_index, count);
      } break;
      // Read some bytes.
      case 1: {
        // Avoid reading past the end of copied_data.
        next_chunk_size =
            std::min(next_chunk_size, copied_data.size() - copy_index);
        size_t count = std::min(next_chunk_size, small_buf.size());
        copy_index +=
            small_buf.NonBlockingRead(copied_data.data() + copy_index, count);
      } break;
    }
  }
  EXPECT_EQ(memcmp(data_.data(), copied_data.data(), kDataSize), 0);
}

TEST_F(RingBufferTest, WriteFullBuffer) {
  EXPECT_EQ(buf_.NonBlockingWrite(data_.data(), buf_.capacity()),
            buf_.capacity());
  EXPECT_TRUE(buf_.full());
  EXPECT_EQ(buf_.NonBlockingWrite(data_.data(), 1), 0);
  EXPECT_TRUE(buf_.full());
}

TEST_F(RingBufferTest, ReadEmptyBuffer) {
  buf_.UnsynchronizedClear();
  EXPECT_TRUE(buf_.empty());
  EXPECT_EQ(buf_.NonBlockingRead(scratch_.data(), 1), 0);
  EXPECT_TRUE(buf_.empty());
}

TEST_F(RingBufferTest, WriteLargerThanBuffer) {
  EXPECT_EQ(buf_.NonBlockingWrite(data_.data(), 2 * buf_.capacity()),
            buf_.capacity());
  EXPECT_TRUE(buf_.full());
}

TEST_F(RingBufferTest, ReadLargerThanBuffer) {
  EXPECT_EQ(buf_.NonBlockingWrite(data_.data(), buf_.capacity()),
            buf_.capacity());
  EXPECT_EQ(buf_.NonBlockingRead(scratch_.data(), buf_.capacity() + 1),
            buf_.capacity());
  EXPECT_TRUE(buf_.empty());
}

// Write all but one element of the buffer, advancing the write index just
// short of the end, then write more than one element.
TEST_F(RingBufferTest, WriteNearlyFull) {
  EXPECT_EQ(buf_.NonBlockingWrite(data_.data(), buf_.capacity() - 1),
            buf_.capacity() - 1);
  EXPECT_EQ(buf_.size(), buf_.capacity() - 1);
  EXPECT_EQ(buf_.NonBlockingWrite(data_.data(), buf_.capacity()), 1);
  EXPECT_EQ(buf_.size(), buf_.capacity());
  EXPECT_TRUE(buf_.full());
}

// Read all but one element of a full buffer, leaving the read index just
// past the start of the buffer, then read more than one element.
TEST_F(RingBufferTest, ReadNearlyEmpty) {
  EXPECT_EQ(buf_.NonBlockingWrite(data_.data(), buf_.capacity()),
            buf_.capacity());
  EXPECT_TRUE(buf_.full());
  EXPECT_EQ(buf_.NonBlockingRead(scratch_.data(), buf_.capacity() - 1),
            buf_.capacity() - 1);
  EXPECT_EQ(buf_.size(), 1);
  EXPECT_EQ(buf_.NonBlockingRead(scratch_.data(), buf_.capacity()), 1);
  EXPECT_EQ(buf_.size(), 0);
  EXPECT_TRUE(buf_.empty());
}

TEST_F(RingBufferTest, BlockingReadWriteTest) {
  std::vector<uint8_t> out;
  std::thread writer = std::thread([&]() { WriteTestData(); });
  std::thread reader = std::thread([&]() { ReadTestData(&out); });
  writer.join();
  reader.join();
  EXPECT_EQ(memcmp(data_.data(), out.data(), kDataSize), 0);
}

// Check operations on the buffer closed flags.
TEST_F(RingBufferTest, ClosedFlags) {
  EXPECT_FALSE(buf_.is_closed_for_read());
  EXPECT_FALSE(buf_.is_closed_for_write());

  // Ensure the read and write flags are independent.
  buf_.close_for_read();
  EXPECT_TRUE(buf_.is_closed_for_read());
  EXPECT_FALSE(buf_.is_closed_for_write());

  buf_.close_for_write();
  EXPECT_TRUE(buf_.is_closed_for_read());
  EXPECT_TRUE(buf_.is_closed_for_write());

  // Ensure we can close the buffer multiple times.
  buf_.close_for_read();
  buf_.close_for_write();
  EXPECT_TRUE(buf_.is_closed_for_read());
  EXPECT_TRUE(buf_.is_closed_for_write());

  // Ensure clearing the buffer resets the flags.
  buf_.UnsynchronizedClear();
  EXPECT_FALSE(buf_.is_closed_for_read());
  EXPECT_FALSE(buf_.is_closed_for_write());
}

}  // namespace asylo
