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

#ifndef ASYLO_PLATFORM_PRIMITIVES_EXTENT_H_
#define ASYLO_PLATFORM_PRIMITIVES_EXTENT_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <type_traits>

namespace asylo {
namespace primitives {

// A extent object suitable for sharing address ranges between trusted and
// untrusted code.
class Extent {
 public:
  // Initializes an empty extent.
  constexpr Extent() : data_(nullptr), size_(0) {}

  // Initializes a extent with a void pointer
  explicit constexpr Extent(void *data, size_t bytes)
      : data_(data), size_(bytes) {}

  // Initializes a extent with a pointer to a value.
  template <typename T>
  explicit constexpr Extent(T *data)
      : data_(raw_pointer(data)), size_(sizeof(T)) {}

  // Initializes a extent with a pointer to an array of |count| objects of type
  // T.
  template <typename T>
  constexpr Extent(T *data, size_t count)
      : data_(raw_pointer(data)), size_(count * sizeof(T)) {}

  // Returns the size of the extent in bytes.
  size_t size() const { return size_; }

  // Returns the extent data as a pointer to an array of bytes.
  void *data() { return data_; }

  // Const overload of Extent::data().
  const void *data() const { return data_; }

  // Returns true if the extent is empty.
  bool empty() const { return data_ == nullptr || size_ == 0; }

  // Returns the extent data as a pointer to an object of type T, or nullptr if
  // the extent is smaller than sizeof(T).
  template <typename T>
  T *As() {
    return size_ >= sizeof(T) ? reinterpret_cast<T *>(data_) : nullptr;
  }

  template <typename T>
  const T *As() const {
    return size_ >= sizeof(T) ? reinterpret_cast<const T *>(data_) : nullptr;
  }

 private:
  template <typename T>
  static constexpr void *raw_pointer(const T *ptr) {
    return reinterpret_cast<void *>(const_cast<T *>(ptr));
  }

  template <typename T>
  static constexpr void *raw_pointer(T *ptr) {
    return reinterpret_cast<void *>(ptr);
  }

  // This method is not intended to be called, it is defined only to provide a
  // scope where offsetof may be applied to private members and Extent is
  // a complete type.
  static void CheckLayout() {
    static_assert(std::is_trivially_copy_assignable<Extent>::value,
                  "Extent must satisfy std::is_trivially_copy_assignable");
    static_assert(std::is_standard_layout<Extent>::value,
                  "Extent must satisfy std::is_standard_layout");
    static_assert(sizeof(size_t) == 8, "Unexpected size for type size_t");
    static_assert(offsetof(Extent, data_) == 0x0,
                  "Unexpected layout for field Extent::data_");
    static_assert(offsetof(Extent, size_) == sizeof(uint64_t),
                  "Unexpected layout for field Extent::size_");
  }

  void *data_;
  size_t size_;
};

// Callback signature for a function which performs custom allocation of
// an Extent.
using ExtentAllocator = std::function<primitives::Extent(size_t)>;

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_EXTENT_H_
