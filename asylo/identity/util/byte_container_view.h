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

#ifndef ASYLO_IDENTITY_UTIL_BYTE_CONTAINER_VIEW_H_
#define ASYLO_IDENTITY_UTIL_BYTE_CONTAINER_VIEW_H_

#include <cstdint>
#include <cstdlib>
#include <iterator>

#include "asylo/util/logging.h"

namespace asylo {

// Byte Container is an abstract concept that is used to represent various
// containers that are used to store bytes (e.g., std::string,
// std::vector<uint8_t>, etc.). A (template) class is considered to
// support the byte-container concept if:
//   1. It provides a value_type type-alias that aliases to the type of bytes
//      stored in that container (e.g., char, uint8_t, etc.).
//   2. It defines the iterator, const_iterator, reverse_iterator, and
//      const_reverse_iterator type aliases.
//   3. It provides an immutable data() method.
//   4. It provides a size() method.
//   5. It provides immutable begin(), end(), cbegin(), cend(), rbegin(),
//      rend(), crbegin(), crend() iterator generators.
//   6. It provides mutable begin(), end(), rbegin(), and rend() iterator
//      generators.
//   7. It provides a resize() method. Note that the resize() method may not
//      necessarily resize the container, and callers of the resize() method
//      must check the size of the byte container after resize operation has
//      been carried out.
//   8. It provides immutable subscript operator and at() method.
//   9. It provides mutable subscript operator and at() method.
//
// byte_container_util.h provides templatized utilities that work with objects
// that support the byte-container concept.
//
// The ByteContainerView class implements the read-only portions of the
// byte-container concept. I.e., it meets requirements 1, 2, 3, 4, 5, and 8
// above.
//
// A ByteContainerView object can be passed as an input into any template
// function that expects a const object that supports the byte-container
// concept.
//
// A ByteContainerView object can be constructed cheaply from a const instance
// of any byte-container object. The view object does not take ownership of the
// underlying memory. It is responsibility of the caller to make sure that the
// underlying memory remains valid for the lifetime of the view object.
class ByteContainerView {
 public:
  using value_type = const uint8_t;
  using const_iterator = const uint8_t *;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;
  using iterator = const_iterator;
  using reverse_iterator = const_reverse_iterator;

  ByteContainerView() = delete;

  ByteContainerView(void const *data, size_t size)
      : data_{reinterpret_cast<const uint8_t *>(data)}, size_{size} {}

  template <typename ByteContainerT>
  ByteContainerView(const ByteContainerT &container)
      : data_{reinterpret_cast<const uint8_t *>(container.data())},
        size_{container.size()} {}

  // Prevent construction of a view object based on a temporary object.
  template <typename ByteContainerT>
  explicit ByteContainerView(const ByteContainerT &&container) = delete;

  const uint8_t *data() const { return data_; }
  size_t size() const { return size_; }

  const_iterator begin() const { return data_; }
  const_iterator end() const { return data_ + size_; }
  const_iterator cbegin() const { return data_; }
  const_iterator cend() const { return data_ + size_; }

  const_reverse_iterator rbegin() const {
    return const_reverse_iterator(end());
  }
  const_reverse_iterator rend() const {
    return const_reverse_iterator(begin());
  }
  const_reverse_iterator crbegin() const {
    return const_reverse_iterator(cend());
  }
  const_reverse_iterator crend() const {
    return const_reverse_iterator(cbegin());
  }

  // Per the conventions of the Standard Library, operator[](size_t) does not
  // perform any bounds checks.
  const uint8_t &operator[](size_t offset) const { return data_[offset]; }

  // Per the conventions of the Standard Library, the at() method performs
  // bounds checks.
  const uint8_t &at(size_t offset) const {
    if (offset >= size_) {
      LOG(FATAL) << "Index out of bounds.";
    }
    return data_[offset];
  }

 private:
  const uint8_t *data_;
  size_t size_;
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_UTIL_BYTE_CONTAINER_VIEW_H_
