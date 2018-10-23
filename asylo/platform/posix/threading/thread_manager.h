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

#ifndef ASYLO_PLATFORM_POSIX_THREADING_THREAD_MANAGER_H_
#define ASYLO_PLATFORM_POSIX_THREADING_THREAD_MANAGER_H_

#include <pthread.h>
#include <functional>
#include <memory>
#include <queue>
#include <utility>

#include "absl/container/flat_hash_map.h"

namespace asylo {

// ThreadManager class is a singleton responsible for:
// - Maintaining a queue of thread start_routine functions.
class ThreadManager {
 public:
  static ThreadManager *GetInstance();

  // Adds the given |function| to a start_routine queue of functions waiting to
  // be run by the pthreads implementation. |arg| will be saved to pass to the
  // start_routine. |thread_id| will be updated to the pthread_t of the created
  // thread.
  int CreateThread(const std::function<void *(void *)> &function, void *arg,
                   pthread_t *thread_id);

  // Removes a function from the start_routine queue and runs it. If no
  // start_routine is present this function will abort().
  int StartThread();

  // Waits till given |thread_id| has returned and assigns its returned void* to
  // |return_value|.
  int JoinThread(pthread_t thread_id, void **return_value);

 private:
  ThreadManager();
  ThreadManager(ThreadManager const &) = delete;
  void operator=(ThreadManager const &) = delete;

  // Represents a thread inside of the enclave.
  struct Thread {
    Thread();
    ~Thread() = default;
    enum class ThreadState { QUEUED, RUNNING, DONE, JOINED };

    // Function passed to pthread_create().
    std::function<void *(void *)> start_routine;

    // Argument passed to pthread_create().
    void *arg;

    // Return value of start_routine.
    void *ret;

    // Guards internal state of a Thread object.
    pthread_mutex_t lock;
    pthread_cond_t state_change_cond;
    pthread_t thread_id;
    ThreadState state;

    // Requires lock is held. Updates the state and broadcasts to
    // state_change_cond and releases the lock.
    int UpdateThreadState(pthread_t thread_id, ThreadState state);
  };

  // Creates a Thread for the given parameters, adds it to the queued_threads_
  // queue then returns a pointer to it.
  std::shared_ptr<Thread> QueueThread(
      const std::function<void *(void *)> &function, void *arg);

  // Adds given |thread| to the threads_ list, sets its state to RUNNING, and
  // returns its thread_id.
  std::shared_ptr<Thread> AllocateThread(std::shared_ptr<Thread> thread);

  // Returns a Thread pointer for a given |thread_id|. Requires
  // LockQueuedThreads().
  std::shared_ptr<Thread> GetThread(pthread_t thread_id);

  // Locks threads_.
  void LockThreadsList();

  // Unlocks threads_.
  void UnlockThreadsList();

  // Locks queued_threads_.
  void LockQueuedThreads();

  // Unlocks queued_threads_.
  void UnlockQueuedThreads();

  // Guards queued_threads_.
  pthread_mutex_t scheduled_lock_;

  // Queue of start_routines waiting to be run.
  // std::shared_ptr is documented to use atomic increments/decrements to manage
  // a refcount instead of using a mutex.
  std::queue<std::shared_ptr<Thread>> queued_threads_;

  // Guards threads_.
  pthread_mutex_t threads_lock_;

  // List of currently running threads or threads waiting to be joined.
  absl::flat_hash_map<pthread_t, std::shared_ptr<Thread>> threads_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_THREADING_THREAD_MANAGER_H_
