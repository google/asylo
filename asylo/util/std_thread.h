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

#ifndef ASYLO_UTIL_STD_THREAD_H_
#define ASYLO_UTIL_STD_THREAD_H_

#include <cstdint>
#include <functional>
#include <thread>

#include "asylo/util/logging.h"

namespace asylo {

// Asylo-specific Thread class to be used in place of std::thread. Rather than
// depend on std::thread directly the Asylo runtime provides this class in order
// to support environments where std::thread is not the preferred thread API.
// It exposes a limited subset of std::thread API and can be extended if
// necessary.
// An executable can only have one implementation of asylo::Thread, to be used
// in all cases a thread needs to be launched.
class Thread {
 public:
  using Id = uint64_t;

  // Creates a joinable thread with a functor (std::function or function
  // pointer) and optional arguments.
  template <class Function, class... Args>
  explicit Thread(Function &&f, Args &&... args)
      : Thread(/*is_detached=*/false, f, args...) {}

  // Move constructor and assign operator.
  Thread(Thread &&other) noexcept = default;
  Thread &operator=(Thread &&other) = default;

  // Disallow copying.
  Thread(const Thread &other) = delete;
  Thread &operator=(const Thread &other) = delete;

  // Static method that starts a detached thread. Creates a thread without
  // returning externally visible Thread object. Allows execution to continue
  // independently of the caller thread. Any resources allocated by
  // StartDetached will be freed once the thread exits.
  template <class Function, class... Args>
  static void StartDetached(Function &&f, Args &&... args) {
    Thread(/*is_detached=*/true, f, args...);
  }

  ~Thread() { CHECK(!thread_.joinable()); }

  // Joins the thread, blocking the current thread until the thread identified
  // by *this finishes execution. Not applicable to detached threads, since
  // StartDetach method does not return Thread object.
  void Join() {
    CHECK_NE(std::this_thread::get_id(), thread_.get_id());
    thread_.join();
  }

  // Returns a unique id of the thread.
  Id get_id() const { return ConvertToId(thread_.get_id()); }

  // Returns the current thread's id (if called within asylo::Thread body,
  // this_thread_id() == get_id()).
  static Id this_thread_id() { return ConvertToId(std::this_thread::get_id()); }

 private:
  // Private constructor creates a joinable or detachable thread with a functor
  // and optional arguments. Used by public constructor and by StartDetached
  // factory method.
  template <class Function, class... Args>
  Thread(bool is_detached, Function &&f, Args &&... args)
      : thread_(
            std::bind(std::forward<Function>(f), std::forward<Args>(args)...)) {
    if (is_detached) {
      thread_.detach();
    }
  }

  static Id ConvertToId(std::thread::id id) {
    static_assert(sizeof(Id) == sizeof(id),
                  "Expected std::thread::id to be an 8 byte entity");
    return *reinterpret_cast<const Id *>(&id);
  }

  std::thread thread_;
};

}  // namespace asylo

#endif  // ASYLO_UTIL_STD_THREAD_H_
