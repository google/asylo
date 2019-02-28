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

#ifndef ASYLO_PLATFORM_PRIMITIVES_UTIL_SERIALIZABLE_THREAD_ID_H_
#define ASYLO_PLATFORM_PRIMITIVES_UTIL_SERIALIZABLE_THREAD_ID_H_

#include <cstdint>
#include <ostream>
#include <thread>

namespace asylo {
namespace primitives {

// Copyable, serializable representation of std::thread:id.
class ThreadId {
 public:
  explicit ThreadId(std::thread::id thread_id) : thread_id_(thread_id) {}
  ThreadId() : ThreadId(std::this_thread::get_id()) {}
  ThreadId(const ThreadId &other) : thread_id_(other.thread_id_) {}
  ThreadId &operator=(const ThreadId &other) {
    thread_id_ = other.thread_id_;
    return *this;
  }

  static const ThreadId Deserialize(uint64_t value);
  uint64_t Serialize() const;

  operator std::thread::id() const { return thread_id_; }

 private:
  std::thread::id thread_id_;
};

bool operator==(const ThreadId &lhs, const ThreadId &rhs);

bool operator!=(const ThreadId &lhs, const ThreadId &rhs);

std::ostream &operator<<(std::ostream &os, const ThreadId &thread_id);

}  // namespace primitives
}  // namespace asylo

// Declare std::hash<ThreadId>, so that it can be used as a key to set/map.
namespace std {
template <>
struct hash<asylo::primitives::ThreadId> {
  std::size_t operator()(const asylo::primitives::ThreadId &id) const {
    return std::hash<std::thread::id>()(id);
  }
};

}  // namespace std

#endif  // ASYLO_PLATFORM_PRIMITIVES_UTIL_SERIALIZABLE_THREAD_ID_H_
