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

#ifndef ASYLO_UTIL_ALIGNED_OBJECT_PTR_H_
#define ASYLO_UTIL_ALIGNED_OBJECT_PTR_H_

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <type_traits>
#include <vector>

namespace asylo {

// An AlignedObjectPtr internally allocates aligned memory for one instance
// of the object, and presents a pointer-like interface (*, ->) to that memory.
// The memory allocated to the embedded object is always owned by the
// AlignedObjectPtr, and must not be managed outside of the AlignedObjectPtr.
// An AlignedObjectPtr instance cannot be copied. However, it can be moved to
// another AlignedObjectPtr instance.
template <class T, size_t Align>
class AlignedObjectPtr {
 public:
  template <typename... Args>
  explicit AlignedObjectPtr(Args &&... args)
      : obj_ptr_{nullptr}, buffer_{nullptr} {
    static_assert(sizeof(T) < (1ULL << 62),
                  "Size of template parameter T is too large.");
    static_assert(Align != 0, "Template parameter Align must not be zero.");
    static_assert(!std::is_array<T>::value,
                  "Template parameter T must not be an array type.");
    size_t alloc_size = sizeof(T) + Align - 1;
    // For consistency with the rest of the code, do not check the value
    // returned by new for nullptr equality.
    buffer_.reset(new uint8_t[alloc_size]);
    uint8_t *aligned_addr = align(Align, buffer_.get());
    obj_ptr_ = new (aligned_addr) T(std::forward<Args>(args)...);
  }

  AlignedObjectPtr(AlignedObjectPtr &&rhs)
      : obj_ptr_{rhs.obj_ptr_}, buffer_{std::move(rhs.buffer_)} {
    rhs.obj_ptr_ = nullptr;
  }

  ~AlignedObjectPtr() {
    if (obj_ptr_ != nullptr) {
      obj_ptr_->~T();
    }
  }

  AlignedObjectPtr &operator=(AlignedObjectPtr &&rhs) {
    if (this == &rhs) {
      return *this;
    }
    if (obj_ptr_ != nullptr) {
      obj_ptr_->~T();
    }
    obj_ptr_ = rhs.obj_ptr_;
    rhs.obj_ptr_ = nullptr;
    buffer_ = std::move(rhs.buffer_);
    return *this;
  }

  // Returns pointer to the allocated object. The AlignedObjectPtr
  // retains ownership of the memory.
  T *get() { return obj_ptr_; }
  const T *get() const { return obj_ptr_; }

  T *operator->() { return get(); }
  const T *operator->() const { return get(); }
  T &operator*() { return *get(); }
  const T &operator*() const { return *get(); }

  // Check if the object is a nullptr.
  explicit operator bool() const { return obj_ptr_ != nullptr; }

  // Check if the input address is aligned.
  static bool IsAligned(const void *addr) {
    return reinterpret_cast<uintptr_t>(addr) % Align == 0;
  }

 private:
  // Aligns a memory address.
  uint8_t *align(size_t alignment, uint8_t *addr) {
    uintptr_t numeric_addr = reinterpret_cast<uintptr_t>(addr);
    uint64_t offset = (alignment - (numeric_addr % alignment)) % alignment;
    return reinterpret_cast<uint8_t *>(numeric_addr + offset);
  }

  // Pointer to the aligned object. This points to a location within the
  // memory held by the buffer_ member below.
  T *obj_ptr_;

  // Smart pointer that points to the actual memory allocated on the heap.
  std::unique_ptr<uint8_t[]> buffer_;
};

}  // namespace asylo

#endif  // ASYLO_UTIL_ALIGNED_OBJECT_PTR_H_
