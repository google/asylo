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

#include <atomic>
#include <functional>
#include <memory>
#include <queue>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace asylo {

bool ReturnFalse();

// ThreadManager class is a singleton responsible for:
// - Maintaining a queue of thread start_routine functions.
class ThreadManager {
 public:
  static ThreadManager *GetInstance();

  // ThreadOptions contains options for configuring new threads.
  struct ThreadOptions {
    // If |detached| a new thread will not be joinable.
    bool detached = false;
  };

  // Adds the given |function| to a start_routine queue of functions waiting to
  // be run by the pthreads implementation. |tid| updates the system thread ID
  // of the new thread. |tls| specifies the pthread TLS address for the new
  // thread, which stores the pthread info that's used by other pthread calls.
  int CreateThread(const std::function<int()> &start_routine, pid_t *tid,
                   void *tls);

  // Removes a function from the start_routine queue and runs it. If no
  // start_routine is present this function will abort(). |tid| is the system
  // thread ID from the host.
  int StartThread(pid_t tid);

  // Updates the result of start function in the ThreadManager.
  void UpdateThreadResult(pthread_t thread_id, void *ret);

  // Waits till given |thread_id| has returned and assigns its returned void* to
  // |return_value|.
  int JoinThread(pthread_t thread_id, void **return_value_out);

  // Detaches the given |thread_id| making it not joinable.
  int DetachThread(pthread_t thread_id);

  // Push a cleanup routine |func| to the current (self) thread.
  void PushCleanupRoutine(const std::function<void()> &func);

  // Pop the top cleanup routine off the current (self) thread; execute it if
  // |execute| is true.
  void PopCleanupRoutine(bool execute);

  // Finalizes the ThreadManager. This means no new threads may be created using
  // pthread_create(). This function will block until all pending
  // pthread_create() created threads have entered the enclave, and all of
  // created threads have returned from |start_routine|.
  void Finalize();

 private:
  ThreadManager() = default;
  ThreadManager(ThreadManager const &) = delete;
  void operator=(ThreadManager const &) = delete;

  // Represents a thread inside of the enclave.
  class Thread {
   public:
    enum class ThreadState { QUEUED, RUNNING, DONE, JOINED };

    // Creates a thread in the QUEUED state with the specified |start_routine|.
    Thread(const ThreadOptions &options, std::function<int()> start_routine,
           void *tls);

    // Sets the system thread ID |tid|.
    void SetTid(pid_t tid);

    // Updates the result from start function.
    void UpdateThreadResult(void *ret);

    // Accessor for the pthread TLS address.
    void *GetThreadTls();

    ~Thread() = default;

    // Moves the thread into the RUNNING state, runs the thread's start_routine,
    // and then sets the state to DONE.
    void Run();

    // Returns the return value of the thread's start routine.
    void *GetReturnValue() const;

    // Returns true if the thread is detached. If true the thread is not
    // joinable.
    bool detached() const;

    // Updates the thread ID; used to bind an Asylo thread struct to the ID of
    // the donated Enclave thread running this Asylo thread.
    void UpdateThreadId(pthread_t thread_id);

    // Accessor for thread id.
    pthread_t GetThreadId();

    // Updates the thread state, potentially unblocking any thread waiting for
    // this thread to enter or exit that state.
    void UpdateThreadState(const ThreadState &state);

    // Blocks until this thread enters |state| or |alternative_predicate|
    // returns true.
    void WaitForThreadToEnterState(
        const ThreadState &state,
        const std::function<bool()> &alternative_predicate = ReturnFalse);

    // Blocks until this thread is not in |state|.
    void WaitForThreadToExitState(const ThreadState &state);

    // Signals any state waiters, in case their predicates may have changed.
    // This allows for predicates to WaitForThreadToEnterState to have
    // conditions that do not necessarily change when the Thread state changes.
    void SignalStateWaiters();

    // Detaches the thread if joinable.
    void Detach();

    // Push cleanup routine |func| onto the thread's cleanup stack.
    void PushCleanupRoutine(const std::function<void()> &func);

    // Pop the top cleanup routine off the thread's cleanup stack; execute it if
    // |execute| is true.
    void PopCleanupRoutine(bool execute);

   private:
    // Run all cleanup routines still on the cleanup stack. This is ony used to
    // run the cleanup stack implicitly when thread execution ends.
    void RunCleanupRoutines();

    // Function passed to pthread_create() bound to its argument.
    const std::function<int()> start_routine_;

    // Return value of start_routine, set when Run() is complete.
    void *ret_;

    // Current thread_id if the thread has been allocated.
    pthread_t thread_id_;

    // Guards internal state of a Thread object.
    pthread_mutex_t lock_ = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t state_change_cond_ = PTHREAD_COND_INITIALIZER;
    ThreadState state_ = ThreadState::QUEUED;
    std::atomic<bool> detached_ = false;

    // The pthread TLS address that saves the thread info.
    void *tls_;

    // Stack of cleanup functions that have been pushed and not yet popped or
    // executed.
    std::stack<std::function<void()>> cleanup_functions_;
  };

  // Adds a Thread object with the given |options| and |start_routine| to
  // queued_threads_. Guaranteed to return a valid std::shared_ptr or this
  // function will abort.
  std::shared_ptr<Thread> EnqueueThread(
      const ThreadOptions &options, const std::function<int()> &start_routine,
      void *tls);

  // Removes a Thread object from queued_threads_ and setups up the Thread with
  // pthread_self() as the thread id and adding it to the threads_ map.
  // Guaranteed to return a valid std::shared_ptr or this function will abort.
  std::shared_ptr<Thread> DequeueThread(pid_t tid);

  // Returns a Thread pointer for a given |thread_id|.
  std::shared_ptr<Thread> GetThread(pthread_t thread_id);

  // Guards queued_threads_ and threads_.
  pthread_mutex_t threads_lock_ = PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t threads_cond_ = PTHREAD_COND_INITIALIZER;

  // Queue of start_routines waiting to be run.
  // std::shared_ptr is documented to use atomic increments/decrements to manage
  // a refcount instead of using a mutex.
  std::queue<std::shared_ptr<Thread>> queued_threads_;

  // List of currently running threads or threads waiting to be joined.
  // ThreadManager is used in trusted contexts where system calls might not be
  // available; avoid using absl based containers which may perform system
  // calls.
  std::unordered_map<pthread_t, std::shared_ptr<Thread>> threads_;

  // Set of thread ids that completed during finalize, but were not joined. Keep
  // track of these in case join is called on the thread after it finishes.
  std::unordered_set<pthread_t> zombie_threads_;

  // Track whether or not we're finalizing the ThreadManager. Once we enter
  // finalize, cleanup/join behavior changes slightly to account for enclaves
  // that don't join all their threads. While finalizing, join becomes a noop
  // and threads are treated as detached as they complete.
  std::atomic<bool> finalizing_{false};
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_THREADING_THREAD_MANAGER_H_
