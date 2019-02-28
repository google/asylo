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

#include "asylo/platform/primitives/util/serializable_thread_id.h"

#include <cstdint>

namespace asylo {
namespace primitives {

const ThreadId ThreadId::Deserialize(uint64_t value) {
  static_assert(sizeof(uint64_t) == sizeof(std::thread::id),
                "Expected std::thread::id to be an 8 byte "
                "entity");
  return ThreadId(*reinterpret_cast<const std::thread::id *>(&value));
}

uint64_t ThreadId::Serialize() const {
  static_assert(sizeof(uint64_t) == sizeof(std::thread::id),
                "Expected std::thread::id to be an 8 byte "
                "entity");
  return *reinterpret_cast<const uint64_t *>(&thread_id_);
}

bool operator==(const ThreadId &lhs, const ThreadId &rhs) {
  return std::thread::id(lhs) == std::thread::id(rhs);
}

bool operator!=(const ThreadId &lhs, const ThreadId &rhs) {
  return !(lhs == rhs);
}

std::ostream &operator<<(std::ostream &os, const ThreadId &thread_id) {
  return os << std::thread::id(thread_id);
}

}  // namespace primitives
}  // namespace asylo
