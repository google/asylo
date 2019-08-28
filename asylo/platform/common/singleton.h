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

#ifndef ASYLO_PLATFORM_COMMON_SINGLETON_H_
#define ASYLO_PLATFORM_COMMON_SINGLETON_H_

#include "absl/synchronization/mutex.h"

namespace asylo {

// Default factory for the template parameter type.
template <typename T>
struct DefaultFactory {
  using value_type = T;
  static T *Construct() { return new T(); }
  static void Destruct(T *t) { delete t; }
};

// The Singleton template class creates a single instance of template parameter
// |T| when needed in a thread-safe fashion. A pointer to this single instance
// may be retrieved through a call to get(). To enable construction of objects
// using non-default constructors, it allows for a second template parameter
// |F|. |F| must be a factory class must provide |T| *Construct() and
// Destruct(|T| *t) methods to enable construction and destruction of objects of
// type |T|.
template <typename T, typename F = DefaultFactory<T>>
class Singleton {
 public:
  // Returns the pointer to the singleton of type |T|. Creates one using the
  // template parameter |F| if none exists. This method is thread-safe.
  static T *get() ABSL_LOCKS_EXCLUDED(mu_) {
    absl::MutexLock lock(&mu_);
    if (instance_) {
      return instance_;
    }

    if (destroyed_) {
      return nullptr;
    }
    if (instance_) {
      return instance_;
    }
    instance_ = F::Construct();
    return instance_;
  }

  // Destroys the singleton using the template parameter |F|. This method is
  // only partially thread-safe. It ensures that instance_ gets destroyed only
  // once, and once destroyed, it cannot be recreated. However, the callers of
  // this method responsible for making sure that no other threads are accessing
  // (or plan to access) the singleton any longer.
  static void Destruct() ABSL_LOCKS_EXCLUDED(mu_) {
    absl::MutexLock lock(&mu_);
    T *tmp_ptr = instance_;
    instance_ = nullptr;
    F::Destruct(tmp_ptr);
    destroyed_ = true;
  }

 private:
  static T *instance_ ABSL_GUARDED_BY(mu_);
  static bool destroyed_ ABSL_GUARDED_BY(mu_);
  static absl::Mutex mu_;
};

template <typename T, typename F>
T *Singleton<T, F>::instance_ = nullptr;

template <typename T, typename F>
bool Singleton<T, F>::destroyed_ = false;

template <typename T, typename F>
absl::Mutex Singleton<T, F>::mu_;

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_SINGLETON_H_
