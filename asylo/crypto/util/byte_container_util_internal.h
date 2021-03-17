/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_UTIL_INTERNAL_H_
#define ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_UTIL_INTERNAL_H_

#include <endian.h>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"

namespace asylo {
namespace internal {

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
                "ByteContainerT must be a string that uses 1-byte characters");

  for (const ByteContainerView &view : views) {
    if (view.size() > std::numeric_limits<uint32_t>::max()) {
      return Status(absl::StatusCode::kInvalidArgument,
                    "Container size exceeds max size");
    }

    // Write the size as a little-endian 32-bit integer.
    uint32_t size_le = htole32(view.size());
    std::copy(reinterpret_cast<char *>(&size_le),
              reinterpret_cast<char *>(&size_le + 1),
              std::back_inserter(*serialized));
    std::copy(view.cbegin(), view.cend(), std::back_inserter(*serialized));
  }

  return absl::OkStatus();
}

// The following overloads of CreateByteContainerViewVector() package their
// input arguments into a vector of ByteContainerView objects and return the
// vector. Seven explicit implementations and one recursive variadic
// implementation are provided. The explicit implementations speed up both the
// compile-time and run-time performance.
inline std::vector<ByteContainerView> CreateByteContainerViewVector() {
  return std::vector<ByteContainerView>();
}

inline std::vector<ByteContainerView> CreateByteContainerViewVector(
    ByteContainerView view) {
  return std::vector<ByteContainerView>({view});
}

inline std::vector<ByteContainerView> CreateByteContainerViewVector(
    ByteContainerView view1, ByteContainerView view2) {
  return std::vector<ByteContainerView>({view1, view2});
}

inline std::vector<ByteContainerView> CreateByteContainerViewVector(
    ByteContainerView view1, ByteContainerView view2, ByteContainerView view3) {
  return std::vector<ByteContainerView>({view1, view2, view3});
}

inline std::vector<ByteContainerView> CreateByteContainerViewVector(
    ByteContainerView view1, ByteContainerView view2, ByteContainerView view3,
    ByteContainerView view4) {
  return std::vector<ByteContainerView>({view1, view2, view3, view4});
}

inline std::vector<ByteContainerView> CreateByteContainerViewVector(
    ByteContainerView view1, ByteContainerView view2, ByteContainerView view3,
    ByteContainerView view4, ByteContainerView view5) {
  return std::vector<ByteContainerView>({view1, view2, view3, view4, view5});
}

inline std::vector<ByteContainerView> CreateByteContainerViewVector(
    ByteContainerView view1, ByteContainerView view2, ByteContainerView view3,
    ByteContainerView view4, ByteContainerView view5, ByteContainerView view6) {
  return std::vector<ByteContainerView>(
      {view1, view2, view3, view4, view5, view6});
}

template <typename... Args>
std::vector<ByteContainerView> CreateByteContainerViewVector(
    ByteContainerView view1, ByteContainerView view2, ByteContainerView view3,
    ByteContainerView view4, ByteContainerView view5, ByteContainerView view6,
    Args... args) {
  std::vector<ByteContainerView> vec1 =
      CreateByteContainerViewVector(view1, view2, view3, view4, view5, view6);
  std::vector<ByteContainerView> vec2 =
      CreateByteContainerViewVector(std::forward<Args>(args)...);
  vec1.reserve(vec1.size() + vec2.size());
  for (const auto &view : vec2) {
    vec1.emplace_back(view);
  }
  return vec1;
}

}  // namespace internal
}  // namespace asylo

#endif  // ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_UTIL_INTERNAL_H_
