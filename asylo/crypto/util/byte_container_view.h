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

#ifndef ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_VIEW_H_
#define ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_VIEW_H_

#include <openssl/mem.h>
#include <string.h>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <type_traits>

#include "absl/strings/string_view.h"
#include "asylo/crypto/util/byte_container_view_internal.h"
#include "asylo/util/logging.h"

namespace asylo {

// Byte Container is an abstract concept that is used to represent various
// containers that are used to store bytes (e.g., std::string,
// std::vector<uint8_t>, etc.). A byte container can be immutable or mutable. An
// immutable byte-container type must meet following requirements:
//   1. It must provide a value_type type-alias that aliases to the type of
//      bytes stored in that container (e.g., char, uint8_t, etc.).
//   2. It must define the iterator, const_iterator, reverse_iterator, and
//      const_reverse_iterator type aliases.
//   3. It must provide an immutable data() method.
//   4. It must provide a size() method.
//   5. It must provide immutable begin(), end(), cbegin(), cend(), rbegin(),
//      rend(), crbegin(), crend() iterator generators.
//   6. It must provide an immutable subscript operator and at() method.
//
// Additionally, a mutable byte container must meet the following supplemental
// requirements:
//   1. It must provide mutable begin(), end(), rbegin(), and rend() iterator
//      generators.
//   2. It must provide a mutable subscript operator and at() method.
//
// The ByteContainerView class is an immutable byte container.
//
// Additionally, a ByteContainerView object can be constructed implicitly and
// cheaply from any other mutable or immutable byte-container objects such as
// another ByteContainerView object or a const instance of any other
// mutable byte-container object. The ByteContainerView object does not take
// ownership of the underlying memory. It is responsibility of the caller to
// make sure that the underlying memory referenced by the ByteContainerView
// remains valid for the lifetime of the ByteContainerView object.

class ByteContainerView {
 public:
  using value_type = const uint8_t;
  using const_iterator = const uint8_t *;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;
  using iterator = const_iterator;
  using reverse_iterator = const_reverse_iterator;

  ByteContainerView() = delete;

  ByteContainerView(const void *data, size_t size)
      : data_{reinterpret_cast<const uint8_t *>(data)}, size_{size} {}

  ByteContainerView(absl::string_view v)
      : data_{reinterpret_cast<const uint8_t *>(v.data())}, size_{v.size()} {}

  ByteContainerView(const char *cstr)
      : data_{reinterpret_cast<const uint8_t *>(cstr)},
        size_{cstr ? strlen(cstr) : 0} {}

  template <size_t kSize>
  constexpr ByteContainerView(const uint8_t (&data)[kSize])
      : data_{data}, size_{kSize} {}

  template <
      typename ByteContainerT,
      typename E = typename std::enable_if<
          internal::is_ro_byte_container_type<ByteContainerT>::value>::type>
  ByteContainerView(const ByteContainerT &container)
      : data_{reinterpret_cast<const uint8_t *>(container.data())},
        size_{container.size()} {}

  const uint8_t *data() const { return data_; }
  size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }

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

  // Returns a const reference to the first element. The behavior is undefined
  // if the empty() method returns true.
  const uint8_t &front() const { return data_[0]; }

  // Returns a const reference to the last element. The behavior is undefined
  // if the empty() method returns true.
  const uint8_t &back() const { return data_[size_ - 1]; }

  // The equality operator. Compares the contents of this ByteContainerView
  // with the contents of |other|.
  bool operator==(ByteContainerView other) const {
    return (size_ == other.size_) && (memcmp(data_, other.data_, size_) == 0);
  }

  // The inequality operator. Compares the contents of this ByteContainerView
  // with the contents of |other|.
  bool operator!=(ByteContainerView other) const { return !operator==(other); }

  // Performs a side-channel-resistant comparison of contents of this
  // ByteContainerView with the contents of |other|. Returns true if the
  // contents are equal.
  bool SafeEquals(ByteContainerView other) const {
    return (size_ == other.size_) &&
           (CRYPTO_memcmp(data_, other.data_, size_) == 0);
  }

 private:
  const uint8_t *data_;
  size_t size_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_VIEW_H_
