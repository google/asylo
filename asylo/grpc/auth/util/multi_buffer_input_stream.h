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

#ifndef ASYLO_GRPC_AUTH_UTIL_MULTI_BUFFER_INPUT_STREAM_H_
#define ASYLO_GRPC_AUTH_UTIL_MULTI_BUFFER_INPUT_STREAM_H_

#include <list>
#include <memory>
#include <vector>

#include <google/protobuf/io/zero_copy_stream.h>

namespace asylo {

using google::protobuf::io::ZeroCopyInputStream;

// The MultiBufferInputStream class provides input stream functionality over
// multiple non-contiguous data buffers.
//
// MultiBufferInputStream implements the ZeroCopyInputStream interface, which is
// designed to minimize copying. For details on the interface, see
// https://developers.google.com/protocol-buffers/docs/reference/cpp/google.protobuf.io.zero_copy_stream.
//
// MultiBufferInputStream also provides several other methods outside the
// ZeroCopyInputStream interface for managing the underlying data buffers and
// stream offset. It is an implicit assumption that the ZeroCopyInputStream
// interface and the additional management interface will not be invoked
// concurrently. While it is perfectly reasonable for both interfaces to be used
// within one program, it is recommended that the logic is clearly separated;
// code using MultiBufferInputStream should act either as a client of the
// ZeroCopyInputStream interface or as a client of the additional functionality
// provided outside that interface.
//
// Unlike most ZeroCopyInputStream implementations, MultiBufferInputStream's
// constructor does not accept parameters that initialize the stream contents.
// Instead, buffers are added to the stream via the AddBuffer() method. This is
// the only time that data is copied.
//
// This class is thread-compatible.
class MultiBufferInputStream : public ZeroCopyInputStream {
 public:
  // Creates an empty stream.
  MultiBufferInputStream();

  // From ZeroCopyInputStream.
  bool Next(const void **data, int *size) override;
  void BackUp(int count) override;
  bool Skip(int count) override;
  int64_t ByteCount() const override;

  // Adds a new buffer containing |size| bytes from |data| to the stream.
  void AddBuffer(const char *data, size_t size);

  // Trims the first ByteCount() bytes from the front of the stream. All
  // unconsumed data in the stream is unaffected. After calling TrimFront(),
  // ByteCount() will return 0 until more data is consumed through a call to
  // Next() or Skip().
  void TrimFront();

  // Rewinds the stream so that all consumed bytes can be re-read. After calling
  // Rewind(), ByteCount() will return 0 until more data is consumed through a
  // call to Next() or Skip().
  void Rewind();

  // Returns a string containing the remaining bytes in the stream. If all data
  // in the stream has already been consumed, this method returns an empty
  // string.
  //
  // This operation is expensive, so calling it frequently, especially when the
  // stream is largely unconsumed, is not recommended. It is provided so that
  // leftover bytes can be copied out of the stream before it is destroyed.
  std::string RemainingBytes() const;

  // Returns the number of unread bytes left in the stream. This is the same as
  // calling RemainingBytes().size() but it is a constant-time operation.
  int RemainingByteCount() const;

 private:
  using BufferList = std::list<std::unique_ptr<std::vector<char>>>;

  BufferList buffers_;

  // Iterator pointing to the current buffer.
  BufferList::const_iterator current_;

  // An offset into the current buffer that indicates the next byte of the
  // stream.
  int offset_;

  // An offset into the first buffer of buffers_ that indicates the beginning of
  // the stream. Data stored at an offset before trim_offset_ is not considered
  // to be part of the stream.
  int trim_offset_;

  // Total bytes read from the start of the stream. This is the byte offset into
  // the entire stream.
  int bytes_read_;

  // The size of the last chunk of bytes returned by Next().
  int last_returned_size_;

  // The total size of the stream in bytes. Bytes before trim_offset_ are not
  // included.
  int size_;
};

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_UTIL_MULTI_BUFFER_INPUT_STREAM_H_
