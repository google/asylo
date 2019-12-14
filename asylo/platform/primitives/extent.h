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
#include <cstring>
#include <functional>
#include <type_traits>

namespace asylo {
namespace primitives {

/// \class Extent extent.h asylo/platform/primitives/extent.h
/// A extent object suitable for sharing address ranges between trusted and
/// untrusted code.
class Extent {
 public:
  /// Initializes an empty extent.
  constexpr Extent() : Extent(/*data=*/nullptr, /*size=*/0) {}

  /// Initializes an extent with a void pointer.
  ///
  /// \param data A pointer to the start of the extent of memory.
  /// \param size The number of bytes in the extent.
  constexpr Extent(void *data, size_t size)
      : data_(data), size_(size) {}

  /// Initializes an extent with a pointer to a value.
  ///
  /// The number of bytes stored for the extent is sizeof(T).
  ///
  /// \param data A pointer to an object of type T
  template <typename T>
  explicit constexpr Extent(T *data)
      : data_(raw_pointer(data)), size_(sizeof(T)) {}

  /// Initializes an extent with a pointer to an array of `count` objects of
  /// type T.
  ///
  /// The size of the extent is `count * sizeof(T)`.
  ///
  /// \param data A pointer to the start of the array slice.
  /// \param count The number of elements included in the extent.
  template <typename T>
  constexpr Extent(T *data, size_t count)
      : data_(raw_pointer(data)), size_(count * sizeof(T)) {}

  /// \returns The size of the extent in bytes.
  size_t size() const { return size_; }

  /// \returns The extent data as a pointer to an array of bytes.
  void *data() { return data_; }

  /// \returns The extent data as a constant pointer to an array of bytes.
  const void *data() const { return data_; }

  /// A predicate for whether the extent is empty.
  /// \returns True if and only if either the extent data is null or the size
  ///    is 0.
  bool empty() const { return data_ == nullptr || size_ == 0; }

  /// Copies the contents of the extent to `out`. The caller is responsible for
  /// allocating and freeing `out` correctly.
  ///
  /// \param out A pointer to a mutable array of bytes.
  void CopyTo(char *out) const {
    memcpy(out, data_, size_);
  }

  /// A size-aware reinterpret_cast for a mutable pointer.
  ///
  /// \returns The extent data as a pointer to an object of type T, or nullptr
  ///    if the extent is smaller than sizeof(T).
  template <typename T>
  T *As() {
    return size_ >= sizeof(T) ? reinterpret_cast<T *>(data_) : nullptr;
  }

  /// A size-aware reinterpret_cast for a constant pointer.
  ///
  /// \returns The extent data as a constant pointer to an object of type T, or
  ///    nullptr if the extent is smaller than sizeof(T).
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

/// The callback signature for a function which performs custom allocation of
/// an Extent.
using ExtentAllocator = std::function<primitives::Extent(size_t)>;

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_EXTENT_H_
