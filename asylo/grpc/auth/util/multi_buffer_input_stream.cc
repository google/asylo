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

#include "asylo/grpc/auth/util/multi_buffer_input_stream.h"

#include "asylo/util/logging.h"

namespace asylo {

MultiBufferInputStream::MultiBufferInputStream()
    : buffers_(BufferList()),
      current_(buffers_.cbegin()),
      offset_(0),
      trim_offset_(0),
      bytes_read_(0),
      last_returned_size_(0),
      size_(0) {}

bool MultiBufferInputStream::Next(const void **data, int *size) {
  if (current_ == buffers_.cend()) {
    return false;
  }

  std::vector<char> *buffer = current_->get();
  if (buffer->size() == offset_) {
    // Advance to the next buffer, if one exists.
    if (++current_ == buffers_.cend()) {
      // Don't let the caller back up.
      last_returned_size_ = 0;
      return false;
    }
    buffer = current_->get();
    offset_ = 0;
  }

  *data = buffer->data() + offset_;
  *size = buffer->size() - offset_;

  last_returned_size_ = buffer->size() - offset_;
  bytes_read_ += last_returned_size_;
  offset_ = buffer->size();

  return true;
}

void MultiBufferInputStream::BackUp(int count) {
  // Last call on the stream did not return any bytes.
  if (last_returned_size_ == 0) {
    LOG(FATAL) << "BackUp() can only be called after a successful call "
               << "to Next()";
  }

  // Invalid backup distance.
  if (count < 0) {
    LOG(FATAL) << "Backup distance must be greater than or equal to 0";
  }

  // Trying to back up too far.
  if (count > last_returned_size_) {
    LOG(FATAL) << "Backup distance must be less than or equal to "
               << "size of last buffer returned by Next()";
  }

  offset_ -= count;
  bytes_read_ -= count;

  // Don't let the caller back up again.
  last_returned_size_ = 0;
}

bool MultiBufferInputStream::Skip(int count) {
  if (current_ == buffers_.cend()) {
    return false;
  }

  // Don't let the caller back up.
  last_returned_size_ = 0;

  while (count > 0) {
    if (current_->get()->size() == offset_) {
      // Advance to the next buffer, if one exists.
      if (++current_ == buffers_.cend()) {
        return false;
      }
      offset_ = 0;
    }

    int bytes_remaining = current_->get()->size() - offset_;
    int bytes_to_skip = (count <= bytes_remaining) ? count : bytes_remaining;

    offset_ += bytes_to_skip;
    bytes_read_ += bytes_to_skip;
    count -= bytes_to_skip;
  }
  return true;
}

int64_t MultiBufferInputStream::ByteCount() const { return bytes_read_; }

void MultiBufferInputStream::AddBuffer(const char *data, size_t size) {
  std::vector<char> *buffer = new std::vector<char>(data, data + size);
  buffers_.emplace_back(std::unique_ptr<std::vector<char>>(buffer));

  // Adjust the current_ pointer in case it was pointing at the end of the list.
  if (current_ == buffers_.cend()) {
    current_--;
  }

  // Update the stream size.
  size_ += size;
}

void MultiBufferInputStream::TrimFront() {
  // Remove all buffers up to the current buffer.
  while (buffers_.cbegin() != current_) {
    buffers_.pop_front();
  }

  if (current_ == buffers_.cend()) {
    // The entire stream has been consumed.
    offset_ = 0;
    trim_offset_ = 0;
  } else if (current_->get()->size() == offset_) {
    // The current buffer has been entirely consumed. Remove it.
    current_++;
    buffers_.pop_front();

    // Update the offsets.
    offset_ = 0;
    trim_offset_ = 0;
  } else {
    // There is some unconsumed data in the current buffer, so it cannot be
    // removed. Update trim_offset_ to indicate the start of valid data in the
    // stream.
    trim_offset_ = offset_;
  }

  // Update the stream size.
  size_ -= bytes_read_;

  // Reset the stream's state.
  last_returned_size_ = 0;
  bytes_read_ = 0;
}

void MultiBufferInputStream::Rewind() {
  current_ = buffers_.cbegin();
  offset_ = trim_offset_;
  last_returned_size_ = 0;
  bytes_read_ = 0;
}

std::string MultiBufferInputStream::RemainingBytes() const {
  std::string contents;
  BufferList::const_iterator it = current_;

  // The entire stream has been consumed.
  if (it == buffers_.cend()) {
    return contents;
  }

  // The first buffer may be partially consumed.
  std::vector<char> *buffer = it->get();
  contents.append(buffer->data() + offset_, buffer->size() - offset_);

  while (++it != buffers_.cend()) {
    buffer = it->get();
    contents.append(buffer->data(), buffer->size());
  }
  return contents;
}

int MultiBufferInputStream::RemainingByteCount() const {
  return size_ - bytes_read_;
}

}  // namespace asylo
