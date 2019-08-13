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

#ifndef ASYLO_IDENTITY_SGX_TCB_CONTAINER_UTIL_H_
#define ASYLO_IDENTITY_SGX_TCB_CONTAINER_UTIL_H_

#include <cstddef>
#include <functional>
#include <string>

#include "asylo/identity/sgx/tcb.pb.h"

namespace asylo {
namespace sgx {

// The types below allow Tcb and RawTcb messages to be used in STL-style hash
// sets and maps.

// An STL-style hasher for Tcb messages.
class TcbHash {
 public:
  size_t operator()(const Tcb &tcb) const;

 private:
  std::hash<std::string> string_hasher_;
};

// An STL-style equality comparator for Tcb messages.
struct TcbEqual {
  bool operator()(const Tcb &lhs, const Tcb &rhs) const;
};

// An STL-style hasher for RawTcb messages.
class RawTcbHash {
 public:
  size_t operator()(const RawTcb &tcbm) const;

 private:
  std::hash<std::string> string_hasher_;
};

// An STL-style equality comparator for RawTcb messages.
struct RawTcbEqual {
  bool operator()(const RawTcb &lhs, const RawTcb &rhs) const;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_TCB_CONTAINER_UTIL_H_
