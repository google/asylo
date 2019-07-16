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

#ifndef ASYLO_PLATFORM_PRIMITIVES_PARAMETER_STACK_H_
#define ASYLO_PLATFORM_PRIMITIVES_PARAMETER_STACK_H_

#include <array>
#include <cstdio>
#include <memory>
#include <type_traits>

#include "absl/strings/str_cat.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/primitive_status.h"

namespace asylo {
namespace primitives {

// A stack of owned Extent objects. An extent is always added as 'owned',
// meaning when the extent is removed, its memory is freed automatically.
// Template parameters provide the appropriate allocator and freer - plain
// function pointers, not std::functions, to accommodate malloc and free.
//
// These two parameters specify an allocation strategy used for the item nodes
// in a linked list representing the stack entries, as well as the Extents
// associated with those nodes. This is provided to enable the same code to
// allocate stack items on the untrusted local heap: directly using
// ParameterStack<malloc, free> by untrusted code, or indirectly using
// ParameterStack<UntrustedLocalAlloc, UntrustedLocalFree> by trusted code. The
// same ParameterStack object can thus be shared between untrusted and trusted
// code.
//
// The class is NOT thread-safe.
template <void *(*ALLOCATOR)(size_t) noexcept, void (*FREER)(void *) noexcept>
class ParameterStack {
 public:
  static_assert(ALLOCATOR != nullptr && FREER != nullptr,
                "ALLOCATOR and FREER may not be null");

  // An individual parameter entry in the parameters list with a link to the
  // next.
  struct Item {
    Item *next;
    Extent extent;

    // Non-copyable object.
    Item(const Item &other) = delete;
    Item &operator=(const Item &other) = delete;

    // Disallow destruction, always call Deleter.
    ~Item() = delete;

    // This method is not intended to be called, it is defined only to provide a
    // scope where offsetof may be applied to members of PrimitiveStack::Item
    // even though ParameterStack is a template rather than a class.
    static void CheckLayout() {
      static_assert(sizeof(size_t) == sizeof(uint64_t),
                    "Unexpected size for type size_t");
      static_assert(
          std::is_standard_layout<Item>::value,
          "ParameterStack::Item must satisfy std::is_standard_layout");
      static_assert(offsetof(Item, next) == 0x0,
                    "Unexpected layout for field "
                    "ParameterStack::Item::next");
      static_assert(offsetof(Item, extent) == 2 * sizeof(uint64_t),
                    "Unexpected layout for field "
                    "ParameterStack::Item::extent");
      static_assert(sizeof(size_t) == 8, "Unexpected size for type size_t");
    }

    // Frees memory allocated for the item using FREER template parameter.
    // Frees parameter extent too. Must be used instead of (disallowed)
    // destructor.
    void Delete() {
      (*FREER)(extent.data());
      (*FREER)(this);
    }
  };

  // Deleter implementation for unique_ptr values returned by Pop.
  class ItemDeleter {
   public:
    explicit ItemDeleter(Item *item) : item_(item) {}
    void operator()(Extent *extent) { item_->Delete(); }

   private:
    Item *item_;
  };

  // Smart pointer to the extent holding on to the item.
  using ExtentPtr = std::unique_ptr<Extent, ItemDeleter>;

  ParameterStack() = default;
  ParameterStack(const ParameterStack &other) = delete;
  ParameterStack operator=(const ParameterStack &other) = delete;

  ~ParameterStack() {
    while (top_) {
      auto item = top_;
      top_ = top_->next;
      item->Delete();
      size_--;
    }
  }

  // Returns whether the stack is empty.
  bool empty() const { return top_ == nullptr; }

  // Returns the number of items on the stack.
  size_t size() const { return size_; }

  // Pops the front extent and releases it, once it goes out of scope. Valid
  // only if !empty().
  ExtentPtr Pop() {
    auto item = top_;
    top_ = item->next;
    item->next = nullptr;
    size_--;
    return std::unique_ptr<Extent, ItemDeleter>(&item->extent,
                                                ItemDeleter(item));
  }

  // Returns the Extent at the top of the stack. Valid only if !empty().
  Extent Top() { return top_->extent; }

  // Allocates and pushes a new extent of the specified size.
  Extent PushAlloc(size_t extent_size) {
    auto item = static_cast<Item *>((*ALLOCATOR)(sizeof(Item)));
    item->extent =
        Extent{static_cast<void *>((*ALLOCATOR)(extent_size)), extent_size};
    item->next = top_;
    top_ = item;
    size_++;
    return item->extent;
  }

  // If invoked inside an enclave, the extent is copied into a buffer allocated
  // on the enclave's trusted heap. Outside the enclave, the extent is copied
  // into a buffer allocated as-by malloc(). In both cases allocated buffers are
  // owned by the stack and will be deleted as-by free() at the end of its
  // lifetime or when Pop-ed from the stack by the handler code.
  // This method is suitable for cases where the lifetime of the stack exceeds
  // the lifetime of the object referred to by |extent|.
  void PushByCopy(Extent extent) {
    auto item = PushAlloc(extent.size());
    if (!extent.empty()) {
      memcpy(item.data(), extent.data(), extent.size());
    }
  }

  // Push and Pop specializations for known type T.  Enable only if T
  // is not a pointer type. More broadly, when used to pass parameters
  // between separate machines, only data which can be fully copied by
  // copying the memory referred to by an extent should be Pushed and
  // Popped.
  template <typename T>
  T Pop() {
    static_assert(!std::is_pointer<T>::value,
                  "ParameterStack should not be used with pointers");
    return *Pop()->template As<T>();
  }

  template <typename T>
  T *PushAlloc() {
    static_assert(!std::is_pointer<T>::value,
                  "ParameterStack should not be used with pointers");
    return PushAlloc(sizeof(T)).template As<T>();
  }

  // Allocate and copy a buffer of known type T and given size. Enable only if T
  // is not a pointer type.
  template <typename T>
  void PushByCopy(const T *buffer, size_t size) {
    static_assert(!std::is_pointer<T>::value,
                  "ParameterStack should not be used with pointers");
    Extent response_extent = PushAlloc(size);
    if (size > 0) {
      memcpy(response_extent.As<T>(), buffer, size);
    }
  }

  template <typename T>
  void PushByCopy(const T &value) {
    static_assert(!std::is_pointer<T>::value,
                  "ParameterStack should not be used with pointers");
    return PushByCopy(Extent{const_cast<T *>(&value)});
  }

#define ASYLO_RETURN_IF_STACK_EMPTY(params)             \
  do {                                                  \
    if (!params->empty()) {                             \
      return {error::GoogleError::INVALID_ARGUMENT,     \
              "Parameter stack expected to be empty."}; \
    }                                                   \
  } while (false)

#define ASYLO_RETURN_IF_INCORRECT_ARGUMENTS(params, expected_args)        \
  do {                                                                    \
    if (params->size() != expected_args) {                                \
      return {error::GoogleError::INVALID_ARGUMENT,                       \
              absl::StrCat(expected_args,                                 \
                           " item(s) expected on the parameter stack.")}; \
    }                                                                     \
  } while (false)

 private:
  // This method is not intended to be called, it is defined only to provide a
  // scope where offsetof may be applied to private members and ParameterStack
  // is a complete type.
  static void CheckLayout() {
    static_assert(std::is_standard_layout<ParameterStack>::value,
                  "ParameterStack must satisfy std::is_standard_layout");
    static_assert(offsetof(ParameterStack, front_) == 0x0,
                  "Unexpected layout for field ParameterStack::front_");
    static_assert(offsetof(ParameterStack, back_) == sizeof(uint64_t),
                  "Unexpected layout for field ParameterStack::back_");
  }

  Item *top_ = nullptr;  // Stack top.
  size_t size_ = 0;
};

// ParameterStack that allocates memory in its local context using malloc and
// free provided by the local environment.
using NativeParameterStack = ParameterStack<malloc, free>;

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_PARAMETER_STACK_H_
