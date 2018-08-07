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

#ifndef ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_UTIL_H_
#define ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_UTIL_H_

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/logging.h"
#include "asylo/util/status.h"

namespace asylo {
namespace internal {

// Encodes |value| as a 32-bit little-endian encoded integer and appends the
// resulting encoding to |buffer|. |value| must not exceed the max value of
// uint32_t.
template <class ByteContainerT>
inline void AppendLittleEndianInt(size_t value, ByteContainerT *buffer) {
// The following check is sufficient for both Clang and GCC.
#ifdef __x86_64__
  std::uint32_t size = value;
  std::copy(reinterpret_cast<char *>(&size),
            reinterpret_cast<char *>(&size + 1), std::back_inserter(*buffer));
#else
#error "Only supported on x86_64 architecture"
#endif
}

}  // namespace internal

// Creates a unique serialization of the views in the |views| vector and appends
// the result to |serialized|. No view in |views| may have a length that exceeds
// the maximum value of a 32-bit integer, otherwise this function returns a
// Status with an INVALID_ARGUMENT error code.
//
// ByteContainerT must be a container that has a 1-byte value_type.
// Addtionally, ByteContainerT must support a push_back() method that pushes a
// new element to the back of the container.
//
// If |views| is a vector V = [x, y, ...], then |serialized| will be set to a
// sequence of bytes S = (len(x) || x || len(y) || y || ...), where len(x) is
// the length of string x encoded as a 32-bit little-endian integer.
template <class ByteContainerT>
Status AppendSerializedByteContainers(
    const std::vector<ByteContainerView> &views, ByteContainerT *serialized) {
  static_assert(sizeof(typename ByteContainerT::value_type) == 1,
                "ByteContainerT must be a std::string that uses 1-byte characters");

  for (const ByteContainerView &view : views) {
    if (view.size() > std::numeric_limits<uint32_t>::max()) {
      return Status(error::GoogleError::INVALID_ARGUMENT,
                    "Container size exceeds max size");
    }
    internal::AppendLittleEndianInt(view.size(), serialized);
    std::copy(view.cbegin(), view.cend(), std::back_inserter(*serialized));
  }

  return Status::OkStatus();
}

// SerializeByteContainers has the same behavior as
// AppendSerializedByteContainers with one difference: the serialized sequence
// is not appended to |serialized|. Instead, the contents of |serialized| are
// overwritten with the serialization.
//
// Note that all the requirements on ByteContainerT stated in the contract for
// AppendSerializedContainers also apply to ByteContainerT in this function.
// Additionally, ByteContainerT must support a clear() method that clears all
// its contents.
template <class ByteContainerT>
Status SerializeByteContainers(const std::vector<ByteContainerView> &views,
                               ByteContainerT *serialized) {
  serialized->clear();
  return AppendSerializedByteContainers(views, serialized);
}

// Copies the contents of a ByteContainerView to a newly created object of type
// ByteContainerT and returns the object by value.
//
// ByteContainerT must have a value_type that is 1-byte in size. Additionally,
// ByteContainerT must have a constructor that accepts an iterator range
// comprising first and last iterators.
template <class ByteContainerT>
ByteContainerT CopyToByteContainer(ByteContainerView view) {
  static_assert(sizeof(typename ByteContainerT::value_type) == 1,
                "ByteContainerT must be a std::string that uses 1-byte characters");
  return ByteContainerT(view.begin(), view.end());
}

// Creates a ConstViewT from the contents of |view|.
//
// ConstViewT must have a 1-byte value_type, and must have a constructor that
// takes const value_type * and size as its parameters.
template <class ConstViewT>
ConstViewT MakeView(ByteContainerView view) {
  static_assert(sizeof(typename ConstViewT::value_type) == 1,
                "ConstViewT must have a 1-byte value_type");
  return ConstViewT(
      reinterpret_cast<const typename ConstViewT::value_type *>(view.data()),
      view.size());
}

// Performs a side-channel-resistant comparison of the contents of two
// ByteContainerView objects. Returns true if the contents are equal.
inline bool SafeCompareByteContainers(ByteContainerView lhs,
                                      ByteContainerView rhs) {
  return lhs.SafeEquals(rhs);
}

}  // namespace asylo

#endif  // ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_UTIL_H_
