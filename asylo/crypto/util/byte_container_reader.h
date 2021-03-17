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

#ifndef ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_READER_H_
#define ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_READER_H_

#include <openssl/mem.h>

#include <cstring>
#include <iterator>
#include <type_traits>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {

// Utility class for reading from an array/stream of bytes. The intended
// use-case is reading packed, variable-length structures in memory.
//
// Internally, ByteContainerReader keeps no copies of any memory, making it
// suitable for working with secrets. It's up to the users of
// ByteContainerReader to clean up any inputs and outputs read/written by
// ByteContainerReader.
class ByteContainerReader {
 public:
  // Create a reader that will consume bytes from |source|. The buffer
  // referenced by |data| should have a lifetime at least as long as the
  // constructed ByteContainerReader object.
  explicit ByteContainerReader(ByteContainerView source)
      : source_(source), offset_(0) {}

  // Create a reader that will consume up to |size| bytes of |data|. The buffer
  // referenced by |data| should have a lifetime at least as long as the
  // constructed ByteContainerReader object.
  ByteContainerReader(const void *data, size_t size)
      : ByteContainerReader(ByteContainerView(data, size)) {}

  ByteContainerReader(const ByteContainerReader &) = delete;
  ByteContainerReader &operator=(const ByteContainerReader &) = delete;

  // Returns the number of bytes still available to be read from the container.
  size_t BytesRemaining() const { return source_.size() - offset_; }

  // Read sizeof(obj) bytes into |obj|. |obj| must be trivially copy assignable.
  template <typename ObjT>
  Status ReadSingle(ObjT *obj) {
    static_assert(std::is_trivially_copy_assignable<ObjT>::value,
                  "ObjT is not trivally copy-assignable");
    return ReadRaw(sizeof(*obj), obj);
  }

  // Append |count| objects onto |output| from the source container. Returns
  // INVALID_ARGUMENT if |count| objects is larger than the number of bytes
  // remaining.
  //
  // ObjContainerT must have a value_type that is trivially copy-assignable,
  // and must support push_back() and back().
  template <typename ObjContainerT>
  Status ReadMultiple(size_t count, ObjContainerT *output) {
    using ValueType = typename ObjContainerT::value_type;
    static_assert(std::is_trivially_copy_assignable<ValueType>::value,
                  "value_type is not trivally copy-assignable");
    const size_t size = count * sizeof(ValueType);
    if (size > BytesRemaining()) {
      return CreateReadTooLargeStatus(size);
    }

    for (size_t i = 0; i < count; ++i) {
      ValueType value;
      // A failure here is "impossible" since we checked the size above.
      ASYLO_CHECK_OK(ReadSingle(&value));
      output->push_back(value);
      OPENSSL_cleanse(&value, sizeof(value));
    }

    return absl::OkStatus();
  }

  // Read |size| bytes directly into the |output| buffer. Returns
  // INVALID_ARGUMENT if |size| is larger than the number of bytes remaining.
  Status ReadRaw(size_t size, void *output) {
    if (size > BytesRemaining()) {
      return CreateReadTooLargeStatus(size);
    }

    memcpy(output, source_.data() + offset_, size);
    offset_ += size;
    return absl::OkStatus();
  }

 private:
  Status CreateReadTooLargeStatus(size_t size) const {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Attempted to read %d bytes, but only %d are available",
                        size, BytesRemaining()));
  }

  const ByteContainerView source_;
  size_t offset_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_READER_H_
