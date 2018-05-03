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

#ifndef ASYLO_IDENTITY_UTIL_BYTE_CONTAINER_UTIL_H_
#define ASYLO_IDENTITY_UTIL_BYTE_CONTAINER_UTIL_H_

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "asylo/util/logging.h"
#include "asylo/util/status.h"

namespace asylo {
namespace internal {

// Encodes |value| as a 32-bit little-endian encoded integer and appends the
// resulting encoding to |buffer|. |value| must not exceed the max value of
// uint32_t.
template <class ContainerT>
void AppendLittleEndianInt(size_t value, ContainerT *buffer) {
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

// Creates a unique string serialization of the containers in the |containers|
// vector and appends the result to |serialized|. No container in |containers|
// may have a length that exceeds the maximum value of a 32-bit integer,
// otherwise this function returns a Status with an INVALID_ARGUMENT error code.
//
// ByteContainerT must expose a value_type type alias and sizeof(typename
// value_type) must be 1. Additionally, ByteContainerT must expose a size()
// method, as well as cbegin() and cend() iterator generators.
//
// StringT must be a specialization of std::basic_string, or some template that
// has a compatible API. Additionally, StringT must use 1-byte characters.
//
// If |containers| is a vector V = [x, y, ...], then |serialized| will be set to
// a string S = (len(x) || x || len(y) || y || ...), where len(x) is the length
// of string x encoded as a 32-bit little-endian integer.
template <class ByteContainerT, class StringT>
Status AppendSerializedByteContainers(
    const std::vector<ByteContainerT> &containers, StringT *serialized) {
  static_assert(sizeof(typename ByteContainerT::value_type) == 1,
                "ByteContainerT must be a std::string that uses 1-byte characters");
  static_assert(sizeof(typename StringT::value_type) == 1,
                "StringT must be a std::string that uses 1-byte characters");

  std::vector<typename StringT::value_type, typename StringT::allocator_type>
      buffer;

  for (const ByteContainerT &container : containers) {
    if (container.size() > std::numeric_limits<uint32_t>::max()) {
      Status status(error::GoogleError::INVALID_ARGUMENT,
                    "Container size exceeds max size");
      LOG(ERROR) << "AppendSerializedBytes failed: " << status;
      return status;
    }
    internal::AppendLittleEndianInt(container.size(), &buffer);
    std::copy(container.cbegin(), container.cend(), std::back_inserter(buffer));
  }
  *serialized +=
      StringT(reinterpret_cast<typename StringT::value_type *>(buffer.data()),
              buffer.size());

  return Status::OkStatus();
}

// SerializeByteContainers has the same behavior as
// AppendSerializedByteContainers with one difference: the serialized sequence
// is not appended to |serialized|. Instead, the contents of |serialized| are
// overwritten with the string serialization.
//
// Note that the requirements on ByteContainerT and StringT stated in the
// contract for AppendSerializedStrings also apply to ByteContainerT and StringT
// in this function.
template <class ByteContainerT, class StringT>
Status SerializeByteContainers(const std::vector<ByteContainerT> &containers,
                               StringT *serialized) {
  serialized->clear();
  return AppendSerializedByteContainers(containers, serialized);
}

}  // namespace asylo

#endif  // ASYLO_IDENTITY_UTIL_BYTE_CONTAINER_UTIL_H_
