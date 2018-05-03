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

#ifndef ASYLO_IDENTITY_UTIL_TEMPLATE_UTIL_H_
#define ASYLO_IDENTITY_UTIL_TEMPLATE_UTIL_H_

#include <type_traits>

namespace asylo {
namespace internal {

// The ValueTypeQualifier template class defines const-qualified value_type and
// const_value_type aliases. ValueTypeQualifier<T>::value_type is the same as
// typename T::value_type if T itself is not a const type. If T is a const type,
// then ValueTypeQualifier::value_type is the same as
// ValueQualifier<T>::const_value_type. ValueTypeQualifier<T>::const_value_type
// is always of type const typename std::remove_const<typename
// T::value_type>::type.
//
// Generic template class definition.
template <typename T>
struct ValueTypeQualifier {
  using value_type = typename T::value_type;
  using const_value_type =
      const typename std::remove_const<typename T::value_type>::type;
};

// Class specialization for const-type template parameter.
template <typename T>
struct ValueTypeQualifier<const T> {
  using value_type =
      typename std::add_const<typename T::value_type>::type;
  using const_value_type =
      typename std::add_const<typename T::value_type>::type;
};

}  // namespace internal
}  // namespace asylo

#endif  // ASYLO_IDENTITY_UTIL_TEMPLATE_UTIL_H_
