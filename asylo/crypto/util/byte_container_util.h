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

#include <vector>

#include "asylo/crypto/util/byte_container_util_internal.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"

namespace asylo {

// Serializes |args| and appends the serializations to |serialized|.
//
// ByteContainerT must have a value_type that is 1-byte in size. Each of |args|
// must be implicitly convertible to a ByteContainerView.
template <class ByteContainerT, typename... Args>
Status AppendSerializedByteContainers(ByteContainerT *serialized,
                                      Args... args) {
  std::vector<ByteContainerView> views =
      internal::CreateByteContainerViewVector(std::forward<Args>(args)...);
  return internal::AppendSerializedByteContainers(views, serialized);
}

// Appends the raw bytes of |obj| to |view|.
//
// ByteContainerT must have a value_type that is 1-byte in size.
template <class ByteContainerT, typename ObjT>
void AppendTrivialObject(const ObjT &obj, ByteContainerT *view) {
  static_assert(std::is_trivially_copy_assignable<ObjT>::value,
                "ObjT is not trivially copy-assignable.");
  static_assert(sizeof(typename ByteContainerT::value_type) == 1,
                "ConstViewT must have a 1-byte value_type");
  ByteContainerView obj_bytes(&obj, sizeof(obj));
  std::copy(obj_bytes.cbegin(), obj_bytes.cend(), std::back_inserter(*view));
}

// Serializes |args| into |serialized|, overwriting any existing contents.
//
// ByteContainerT must have a value_type that is 1-byte in size. Each of |args|
// must be implicitly convertible to a ByteContainerView.
template <class ByteContainerT, typename... Args>
Status SerializeByteContainers(ByteContainerT *serialized, Args... args) {
  serialized->clear();
  std::vector<ByteContainerView> views =
      internal::CreateByteContainerViewVector(std::forward<Args>(args)...);
  return internal::AppendSerializedByteContainers(views, serialized);
}

// Copies the contents of a ByteContainerView to a newly created object of type
// ByteContainerT and returns the object by value.
//
// ByteContainerT must have a value_type that is 1-byte in size. Additionally,
// ByteContainerT must have a constructor that accepts an iterator range
// comprising first and last iterators.
template <class ByteContainerT>
ByteContainerT CopyToByteContainer(ByteContainerView view) {
  static_assert(
      sizeof(typename ByteContainerT::value_type) == 1,
      "ByteContainerT must be a container that uses 1-byte characters");
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
