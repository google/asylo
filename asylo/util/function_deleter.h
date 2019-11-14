/*
 *
 * Copyright 2019 Asylo authors
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

#ifndef ASYLO_UTIL_FUNCTION_DELETER_H_
#define ASYLO_UTIL_FUNCTION_DELETER_H_

namespace asylo {

// A deleter struct that wraps a free()-like function. Can be used as the second
// template parameter to a std::unique_ptr<...> when a pointer has been
// allocated using a custom or wrapper allocator.
template <void (*FreeFunction)(void *)>
struct FunctionDeleter {
  void operator()(void *ptr) { FreeFunction(ptr); }
};

// A deleter struct that wraps a free()-like function whose pointer parameter
// has a non-void type. Can be used as the second template parameter to a
// std::unique_ptr<T, ...> for C types with custom free functions.
template <typename T, void (*FreeFunction)(T *)>
struct TypedFunctionDeleter {
  void operator()(T *ptr) { FreeFunction(ptr); }
};

}  // namespace asylo

#endif  // ASYLO_UTIL_FUNCTION_DELETER_H_
