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

#ifndef ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_VIEW_INTERNAL_H_
#define ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_VIEW_INTERNAL_H_

#include <type_traits>

namespace asylo {
namespace internal {

// A traits class that exposes a static constexpr boolean member called value.
// This member is set to true if ByteContainerT supports the read-only
// byte-container API outlined in byte_container_view.h, else it is set to
// false.
template <typename ByteContainerT>
struct is_ro_byte_container_type {
 private:
  // A restrictive definition of CheckSize that gets selected if ByteContainerU
  // defines a type alias called value_type, and the size of that type is one
  // byte.
  template <typename ByteContainerU,
            typename E = typename std::enable_if<
                sizeof(typename ByteContainerU::value_type) == 1>::type>
  static std::true_type CheckSize(const ByteContainerU *u);

  // A non-restrictive definition of CheckSize that gets selected if the above
  // definition is not selected.
  template <typename ByteContainerU>
  static std::false_type CheckSize(...);

  using size_type = decltype(
      CheckSize<ByteContainerT>(static_cast<const ByteContainerT *>(0)));

  // A restrictive definition of the CheckApi method that gets selected when
  // ByteContainerU supports the read-only byte-container API. The return type
  // of this method is std::true_type.
  template <typename ByteContainerU>
  static auto CheckApi(const ByteContainerU *u)
      -> decltype(u->data(), u->size(), u->begin(), u->end(), u->cbegin(),
                  u->cend(), u->rbegin(), u->rend(), u->crbegin(), u->crend(),
                  u->at(0), u->operator[](0),
                  typename ByteContainerU::iterator(),
                  typename ByteContainerU::const_iterator(),
                  typename ByteContainerU::reverse_iterator(),
                  typename ByteContainerU::const_reverse_iterator(),
                  std::true_type());

  // A non-restrictive definition of the CheckApi method that gets selected if
  // the restrictive method is not selected. The return type of this method is
  // std::false_type.
  template <typename ByteContainerU>
  static std::false_type CheckApi(...);

  using api_type = decltype(
      CheckApi<ByteContainerT>(static_cast<const ByteContainerT *>(0)));

 public:
  static constexpr bool value = api_type::value & size_type::value;
};

}  // namespace internal
}  // namespace asylo

#endif  // ASYLO_CRYPTO_UTIL_BYTE_CONTAINER_VIEW_INTERNAL_H_
