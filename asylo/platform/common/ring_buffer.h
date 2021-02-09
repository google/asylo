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

#ifndef ASYLO_PLATFORM_COMMON_RING_BUFFER_H_
#define ASYLO_PLATFORM_COMMON_RING_BUFFER_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace asylo {

// A synchronized queue of bytes supporting exactly one reader and exactly one
// writer. The case of sharing a buffer between multiple simultaneous readers or
// writers is not supported and will corrupt the buffer contents.
//
// NOTE: This code is written with security sensitive applications in mind, and
// care should be taken to ensure it never reads or writes outside the stack
// object itself. In particular, while we assume the integrity of the code
// accessing the buffer, we make no assumptions about the integrity of the data
// in the buffer itself.
//
// This implementation is intended for applications which can't use operating
// system synchronization primitives, for instance embedded applications on bare
// hardware. Only atomic instructions are used for synchronization and the
// availability of mechanisms like condition variables is not assumed.
//
// All read and write operations address the buffer with indices modulo a buffer
// size specified at compile time. This means that corruption of runtime data
// cannot cause the calling thread to access memory outside the bounds of the
// object itself.
//
// A simple versioning scheme is supported to confirm the compatibility of
// objects and types at runtime, as this type is intended to remain compatible
// between different compiler and source versions. If the layout of an instance
// matches the expected layout of a type then:
//
// RingBuffer<kCapacity>::TypeVersion() == instance->InstanceVersion();
//

// Exposes NonBlockingRead/Write for testing.
template <size_t kCapacity>
class RingBufferForTest;

template <size_t kCapacity>
class RingBuffer {
 public:
  static_assert(kCapacity > 1, "Minimum supported size is two elements.");

  // C++11 does not provide a constexpr version of is_lock_free, so instead
  // check that an atomic size_t has the same size as regular size_t. This
  // ensures that a std::atomic<size_t> is a bare machine word we can share with
  // (for instance) a device or virtual machine.
  static_assert(sizeof(std::atomic<size_t>) == sizeof(size_t),
                "std::atomic<size_t> is not lock free.");

  RingBuffer()
      : instance_version_(RingBuffer<kCapacity>::TypeVersion()),
        closed_for_read_(0),
        closed_for_write_(0),
        count_(0),
        read_pos_(0),
        write_pos_(0) {}

  RingBuffer(const RingBuffer<kCapacity> &) = delete;

  RingBuffer(RingBuffer<kCapacity> &&) = delete;

  RingBuffer<kCapacity> &operator=(const RingBuffer &) = delete;

  RingBuffer<kCapacity> &operator=(RingBuffer &&) = delete;

  // Reads from the buffer, blocking if data is unavailable.
  size_t Read(uint8_t *buf, size_t nbyte) {
    if (closed_for_read_) {
      return 0;
    }

    size_t already_read = 0;
    while (nbyte - already_read > 0) {
      while (empty()) {
        if (closed_for_write_) return already_read;
        std::this_thread::yield();
      }
      already_read += NonBlockingRead(buf + already_read, nbyte - already_read);
    }
    return already_read;
  }

  // Writes to the buffer, blocking if the buffer is full.
  size_t Write(const uint8_t *buf, size_t nbyte) {
    if (closed_for_write_) {
      return 0;
    }

    size_t already_written = 0;
    while (nbyte - already_written > 0) {
      while (full()) {
        if (closed_for_read_) return already_written;
        std::this_thread::yield();
      }
      already_written +=
          NonBlockingWrite(buf + already_written, nbyte - already_written);
    }
    return already_written;
  }

  // Sets the closed-for-write flag, indicating that no more writes to this
  // buffer are expected and the reader should not wait for more data.
  void close_for_write() { closed_for_write_ = 1; }

  // Sets the closed-for-read flag, indicating that no more reads to this buffer
  // are expected and the writer should not wait to write more data.
  void close_for_read() { closed_for_read_ = 1; }

  // Returns the closed-for-write flag.
  bool is_closed_for_write() const { return closed_for_write_ != 0; }

  // Returns the closed-for-read flag.
  bool is_closed_for_read() const { return closed_for_read_ != 0; }

  // Returns the maximum capacity of the buffer in bytes.
  constexpr size_t capacity() const { return kCapacity; }

  // Clears the buffer and leaves it empty. This operation is not synchronized
  // and its behavior in the presence of concurrent readers and writers is
  // undefined.
  void UnsynchronizedClear() {
    closed_for_read_ = 0;
    closed_for_write_ = 0;
    count_ = 0;
    read_pos_ = 0;
    write_pos_ = 0;
  }

  // Returns the number of bytes of empty space available for writing.
  size_t available() const { return kCapacity - count_; }

  // Returns number of bytes stored in the buffer for reading.
  size_t size() const { return count_; }

  // Returns true is the buffer is empty.
  bool empty() const { return count_ == 0; }

  // Returns true is the buffer is full.
  bool full() const { return count_ == kCapacity; }

  // Returns a signature reflecting the layout of this concrete instance.
  uint64_t InstanceVersion() const { return instance_version_; }

  // Returns a signature reflecting the layout of this abstract type.
  static constexpr uint64_t TypeVersion() {
    return offsetof(RingBuffer, count_) << 0 |
           offsetof(RingBuffer, closed_for_read_) << 8 |
           offsetof(RingBuffer, closed_for_write_) << 16 |
           offsetof(RingBuffer, read_pos_) << 24 |
           offsetof(RingBuffer, write_pos_) << 32 |
           offsetof(RingBuffer, buffer_) << 40 | sizeof(RingBuffer) << 48;
  }

 private:
  friend class RingBufferForTest<kCapacity>;

  // Reads up to |nbyte| bytes without blocking, returning the number
  // successfully read.
  size_t NonBlockingRead(uint8_t *buf, size_t nbyte) {
    // Since there is only one reader, and since the writer will only ever add
    // bytes to the buffer, we can read at least size bytes.
    size_t size = std::min(nbyte, count_.load());
    if (size == 0) {
      return 0;
    }

    // There are two contiguous runs of bytes we can read from the buffer: one
    // to the right of read_index, and potentially one on the left if the run
    // wraps around to zero. The following calls to memcpy read those bytes
    // into |buf|.
    //
    // Note that although read_pos_ should already be in bounds, we double
    // check when reading it into right_index. This is required to avoid a
    // time-of-use / time-of-check vulnerability in the event an attacker has
    // corrupted the shared buffer.
    size_t right_index = read_pos_ % kCapacity;
    size_t right_count = std::min(size, kCapacity - right_index);
    memcpy(buf, buffer_.data() + right_index, right_count);
    if (size - right_count > 0) {
      // Reading from the left.
      memcpy(buf + right_count, buffer_.data(), size - right_count);
    }

    // Decrement the count of bytes in the buffer atomically since the writer
    // may be incrementing it concurrently.
    count_.fetch_add(-size);
    read_pos_ = (read_pos_ + size) % kCapacity;

    return size;
  }

  // Writes up to |nbyte| bytes without blocking, returning the number
  // successfully written.
  size_t NonBlockingWrite(const uint8_t *buf, size_t nbyte) {
    // Since there is only one writer, and since the reader will only ever
    // remove bytes from the buffer, we can write at least size bytes.
    size_t size = std::min(nbyte, kCapacity - count_);
    if (size == 0) {
      return 0;
    }

    // There are two contiguous empty gaps where we can write to in the
    // buffer: one to the right of right_index, and potentially one on the
    // left if the gap wraps around to zero. The following calls to memcpy
    // fill those gaps from |buf|.
    //
    // The "% kCapacity" here is required and should not be removed. See
    // NonBlockingRead for a discussion.
    size_t right_index = write_pos_ % kCapacity;
    size_t right_count = std::min(size, kCapacity - right_index);
    memcpy(buffer_.data() + right_index, buf, right_count);
    if (size - right_count > 0) {
      // Writing to the left.
      memcpy(buffer_.data(), buf + right_count, size - right_count);
    }

    // Increment the count of bytes in the buffer atomically since the reader
    // may be decrementing it concurrently.
    count_.fetch_add(size);
    write_pos_ = (write_pos_ + size) % kCapacity;

    return size;
  }

  const uint64_t instance_version_;         // Layout of the struct.
  std::atomic<uint32_t> closed_for_read_;   // Reader is done reading.
  std::atomic<uint32_t> closed_for_write_;  // Writer is done writing.
  std::atomic<size_t> count_;  // Number of bytes waiting in the queue.
  volatile size_t read_pos_;   // Read index into buffer_.
  volatile size_t write_pos_;  // Write index into buffer_.
  std::array<uint8_t, kCapacity> buffer_;
} __attribute__((aligned(8)));  // Ensure 64-bit alignment;

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_RING_BUFFER_H_
