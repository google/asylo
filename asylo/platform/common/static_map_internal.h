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

#ifndef ASYLO_PLATFORM_COMMON_STATIC_MAP_INTERNAL_H_
#define ASYLO_PLATFORM_COMMON_STATIC_MAP_INTERNAL_H_

#include <type_traits>
#include <utility>

namespace asylo {
namespace internal {

// The ValueIterator template class can be used to define an iterator over the
// T values contained in a static map.
template <typename T, typename MapIteratorT>
class ValueIterator : public MapIteratorT {
 public:
  using difference_type = typename MapIteratorT::difference_type;
  using value_type = T;
  using pointer = T *;
  using reference = T &;
  using iterator_category = typename MapIteratorT::iterator_category;

  ValueIterator() = default;

  // Constructs a static map iterator from an rvalue reference of the underlying
  // MapIteratorT.
  explicit ValueIterator(MapIteratorT &&iter) : MapIteratorT(std::move(iter)) {}

  // Constructs a const static-map iterator from a mutable static-map iterator.
  // This constructor is made implicit to comply with C++ Standard Library
  // requirements for iterator types.
  template <typename MapIteratorU>
  ValueIterator(
      ValueIterator<typename std::remove_const<T>::type, MapIteratorU> other)
      : MapIteratorT(static_cast<MapIteratorU>(other)) {}

  // Returns a reference to the instance of T that is pointed to by this
  // iterator.
  T &operator*() { return *MapIteratorT::operator*().second; }

  // Returns a pointer to the instance of T that is pointed to by this
  // iterator.
  T *operator->() { return MapIteratorT::operator->()->second; }
};

}  // namespace internal
}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_STATIC_MAP_INTERNAL_H_
