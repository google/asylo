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

#ifndef ASYLO_CRYPTO_UTIL_TRIVIAL_OBJECT_UTIL_H_
#define ASYLO_CRYPTO_UTIL_TRIVIAL_OBJECT_UTIL_H_

#include <type_traits>

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include <openssl/rand.h>

namespace asylo {


template <class T>
bool SetTrivialObjectFromHexString(absl::string_view view, T *obj) {
#ifndef __ASYLO__
  static_assert(std::is_trivially_copy_assignable<T>::value,
                "Template parameter is not trivially copy-assignable.");
#endif  // __ASYLO__
  // Make sure that the string has correct number of hex characters
  // to exactly fill obj, and that obj is not a nullptr.
  if (view.size() != sizeof(T) * 2 || obj == nullptr) {
    return false;
  }
  for (auto ch : view) {
    if (std::isxdigit(ch) == 0) {
      return false;
    }
  }
  absl::HexStringToBytes(view).copy(reinterpret_cast<char *>(obj),
                                    sizeof(*obj));
  return true;
}

template <class T>
std::string ConvertTrivialObjectToHexString(const T &obj) {
#ifndef __ASYLO__
  static_assert(std::is_trivially_copy_assignable<T>::value,
                "Template parameter is not trivially copy-assignable.");
#endif  // __ASYLO__
  return absl::BytesToHexString(
      absl::string_view(reinterpret_cast<const char *>(&obj), sizeof(obj)));
}

template <class T>
T TrivialRandomObject() {
#ifndef __ASYLO__
  static_assert(std::is_trivially_copy_assignable<T>::value,
                "Template parameter is not trivially copy-assignable.");
#endif  // __ASYLO__
  T tmp;
  RAND_bytes(reinterpret_cast<uint8_t *>(&tmp), sizeof(tmp));
  return tmp;
}

template <class T>
T TrivialZeroObject() {
#ifndef __ASYLO__
  static_assert(std::is_trivially_copy_assignable<T>::value,
                "Template parameter is not trivially copy-assignable.");
#endif  // __ASYLO__
  T tmp;
  memset(&tmp, 0, sizeof(tmp));
  return tmp;
}

template <class T>
T TrivialOnesObject() {
#ifndef __ASYLO__
  static_assert(std::is_trivially_copy_assignable<T>::value,
                "Template parameter is not trivially copy-assignable.");
#endif  // __ASYLO__
  T tmp;
  memset(&tmp, 0xff, sizeof(tmp));
  return tmp;
}

template <class T>
const T &TrivialObjectFromBinaryString(absl::string_view view) {
#ifndef __ASYLO__
  static_assert(std::is_trivially_copy_assignable<T>::value,
                "Template parameter is not trivially copy-assignable.");
#endif  // __ASYLO__
  return *reinterpret_cast<const T *>(view.data());
}

}  // namespace asylo

#endif  // ASYLO_CRYPTO_UTIL_TRIVIAL_OBJECT_UTIL_H_
