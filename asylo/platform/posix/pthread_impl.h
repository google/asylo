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

#ifndef ASYLO_PLATFORM_POSIX_PTHREAD_IMPL_H_
#define ASYLO_PLATFORM_POSIX_PTHREAD_IMPL_H_

#include <pthread.h>
#include <functional>

#include "asylo/util/logging.h"

namespace asylo {
namespace pthread_impl {

// Utility class for working with pthread_list_t.
class PthreadListWrapper {
 public:
  // The PthreadListWrapper does not take ownership of |mutex|.
  PthreadListWrapper(pthread_mutex_t* mutex);
  // The PthreadListWrapper does not take ownership of |condvar|.
  PthreadListWrapper(pthread_cond_t* condvar);

  // This constructor should only be used for testing. Use one of the above
  // constructors which takes a pthread_* type. The PthreadListWrapper does not
  // take ownership of |list|.
  PthreadListWrapper(__pthread_list_t* list,
                     const std::function<void()>& abort_func = abort);

  // Removes the first thread_id in the list.
  void Pop();

  // Adds |id| to the end of the list.
  void Push(const pthread_t id);

  // Returns true if |id| is found and removed from the list; false if not
  // found.
  bool Remove(const pthread_t id);

  // Removes all ids from the list.
  void Drain();

  // Returns true of the |id| is in the list.
  bool Contains(const pthread_t id) const;

  // Returns the first id in the list.
  pthread_t Front() const;

  // Returns true if the id is in the list.
  bool Empty() const;

 private:
  __pthread_list_t* const list_;

  std::function<void()> abort_func_;
};

// Provides an RAII wrapper around pthread_mutex_t. Aborts on errors, so should
// only be used for locks that are internal to pthread.cc, where errors indicate
// internal implementation errors. Should not be used for user-provided mutexes
// so that we don't abort internally due to application error.
class PthreadMutexLock {
 public:
  PthreadMutexLock(pthread_mutex_t* mutex) : mutex_(mutex) {
    int ret = pthread_mutex_lock(mutex_);
    if (ret != 0) {
      LOG(FATAL) << "Can't lock mutex: " << ret;
      abort();
    }
  }

  ~PthreadMutexLock() {
    int ret = pthread_mutex_unlock(mutex_);
    if (ret != 0) {
      LOG(FATAL) << "Can't unlock mutex: " << ret;
      abort();
    }
  }

 private:
  pthread_mutex_t* const mutex_;
};

}  // namespace pthread_impl
}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_PTHREAD_IMPL_H_
