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

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>

#include <array>
#include <bitset>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <type_traits>

#include "asylo/platform/common/enclave_state.h"
#include "asylo/platform/common/time_util.h"
#include "asylo/platform/core/atomic.h"
#include "asylo/platform/core/trusted_global_state.h"
#include "asylo/platform/host_call/trusted/host_calls.h"
#include "asylo/platform/posix/include/semaphore.h"
#include "asylo/platform/posix/pthread_impl.h"
#include "asylo/platform/posix/syscall/enclave_clone.h"
#include "asylo/platform/posix/threading/thread_manager.h"
#include "asylo/platform/primitives/trusted_runtime.h"
#include "asylo/platform/primitives/util/trusted_memory.h"

namespace {

constexpr size_t kNumSpinLockAttempts = 10000;

static void (*tsd_destructors[PTHREAD_KEYS_MAX])(void *) = {0};
static pthread_rwlock_t key_lock = PTHREAD_RWLOCK_INITIALIZER;
static void NoDestructor(void *placeholder) {}
size_t __pthread_tsd_size = sizeof(void *) * PTHREAD_KEYS_MAX;

inline int pthread_spin_lock(pthread_spinlock_t *lock) {
  constexpr unsigned int kLocked = 1;
  constexpr unsigned int kUnlocked = 0;
  while (asylo::AtomicExchange(lock, kLocked, std::memory_order_acquire) !=
         kUnlocked) {
    while (*lock) {
      enc_pause();
    }
  }
  return 0;
}

inline int pthread_spin_unlock(pthread_spinlock_t *lock) {
  asylo::AtomicClear(lock, std::memory_order_release);
  return 0;
}

// Initializes an untrusted wait queue. Will do nothing if enclave is not yet
// running, if called during enclave startup.
inline void initialize_wait_queue(int32_t **wait_queue_ptr) {
  if (wait_queue_ptr && !(*wait_queue_ptr) &&
      asylo::GetState() == asylo::EnclaveState::kRunning) {
    *wait_queue_ptr = enc_untrusted_create_wait_queue();
    CHECK_NE(*wait_queue_ptr, nullptr);
  }
}

// An RAII guard object managing exclusive access to a "lockable" object, where
// a lockable object is an aggregate type with a field "lock_" of type
// pthread_spinlock_t.
class LockableGuard {
 public:
  template <class LockableType>
  LockableGuard(LockableType *lockable) : LockableGuard(&lockable->_lock) {}

  // Initializes a guard with an explicit reference to a lock instance, rather
  // than a lockable's |lock_| field.
  LockableGuard(pthread_spinlock_t *lock) : lock_(lock) {
    pthread_spin_lock(lock_);
  }

  ~LockableGuard() { pthread_spin_unlock(lock_); }

  void Lock() { pthread_spin_lock(lock_); }

  void Unlock() { pthread_spin_unlock(lock_); }

 private:
  pthread_spinlock_t *const lock_;
};

__pthread_list_node_t *alloc_list_node(pthread_t thread_id) {
  __pthread_list_node_t *node = new __pthread_list_node_t;
  node->_thread_id = thread_id;
  node->_next = nullptr;
  return node;
}

void free_list_node(__pthread_list_node_t *node) { delete node; }

int pthread_mutex_check_parameter(pthread_mutex_t *mutex) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_mutex_t>(mutex)) {
    return EFAULT;
  }

  if (mutex->_control != PTHREAD_MUTEX_RECURSIVE &&
      mutex->_control != PTHREAD_MUTEX_NONRECURSIVE) {
    return EINVAL;
  }
  return 0;
}

// Returns locks the mutex and returns 0 if possible. Returns EBUSY if the mutex
// is taken. |mutex|->_lock must be locked.
int pthread_mutex_lock_internal(pthread_mutex_t *mutex) {
  const pthread_t self = pthread_self();

  if (mutex->_control == PTHREAD_MUTEX_RECURSIVE && mutex->_owner == self) {
    mutex->_refcount++;
    return 0;
  }

  if (mutex->_owner != PTHREAD_T_NULL) {
    return EBUSY;
  }
  mutex->_owner = self;
  mutex->_refcount++;
  if (mutex->_untrusted_wait_queue) {
    enc_untrusted_enable_waiting(mutex->_untrusted_wait_queue);
  }
  return 0;
}

// Read locks the given |rwlock| if possible and returns 0. On success,
// |rwlock|._readers is incremented. Returns EBUSY if the |rwlock| is write
// locked. |rwlock|._lock must be locked by the caller.
int pthread_rwlock_tryrdlock_internal(pthread_rwlock_t *rwlock) {
  // If |rwlock| is owned by a writer it is not read lockable.
  if (rwlock->_write_owner != PTHREAD_T_NULL) {
    return EBUSY;
  }

  rwlock->_reader_count++;
#ifdef _ASYLO_PTHREAD_RWLOCK_TRANSITIONAL_FLAG
  if (rwlock->_untrusted_wait_queue) {
    enc_untrusted_enable_waiting(rwlock->_untrusted_wait_queue);
  }
#endif
  return 0;
}

// Write locks the given |rwlock| if possible and returns 0. On success,
// |rwlock|._write_owner is set to pthread_self().  Returns EBUSY if the
// |rwlock| is write locked or read locked. |rwlock|._lock must be locked by the
// caller.
int pthread_rwlock_trywrlock_internal(pthread_rwlock_t *rwlock) {
  // If |rwlock| is owned by a reader it is not write lockable.
  if (rwlock->_reader_count != 0) {
    return EBUSY;
  }

  // If |rwlock| is owned by the current thread there is a deadlock.
  const pthread_t self = pthread_self();
  if (rwlock->_write_owner == self) {
    return EDEADLK;
  }

  // If |rwlock| is owned by another writer it is not write lockable.
  if (rwlock->_write_owner != PTHREAD_T_NULL) {
    return EBUSY;
  }

  rwlock->_write_owner = self;
#ifdef _ASYLO_PTHREAD_RWLOCK_TRANSITIONAL_FLAG
  if (rwlock->_untrusted_wait_queue) {
    enc_untrusted_enable_waiting(rwlock->_untrusted_wait_queue);
  }
#endif
  return 0;
}

// Small utility function to "convert" a return value into an errno value. The
// sem_* functions indicate errors by returning -1 and setting the global errno
// variable to the error value. Unfortunately, this is different than the
// pthread_cond_* and pthread_mutex_* functions that indicate errors by
// returning the error value directly.
int ConvertToErrno(int err_value) {
  if (err_value == 0) {
    return 0;
  }

  errno = err_value;
  return -1;
}

// Returns a ThreadManager::ThreadOptions from the configuration of |attr|.
asylo::ThreadManager::ThreadOptions CreateOptions(
    const pthread_attr_t *const attr) {
  asylo::ThreadManager::ThreadOptions options;

  if (attr && attr->detach_state == PTHREAD_CREATE_DETACHED) {
    options.detached = true;
  }

  return options;
}

// Acquires |rwlock| with a read lock or a write lock if |TryLockFunc| is
// set to pthread_rwlock_tryrdlock_internal() or
// pthread_rwlock_trywrlock_internal() respectively.
template <int(TryLockFunc)(pthread_rwlock_t *)>
int pthread_rwlock_lock(pthread_rwlock_t *rwlock) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_rwlock_t>(rwlock)) {
    return ConvertToErrno(EFAULT);
  }

#ifdef _ASYLO_PTHREAD_RWLOCK_TRANSITIONAL_FLAG
  if (!rwlock->_untrusted_wait_queue) {
    LockableGuard lock_guard(rwlock);
    initialize_wait_queue(&rwlock->_untrusted_wait_queue);
  }
#endif

  const pthread_t self = pthread_self();
  asylo::pthread_impl::QueueOperations queue(rwlock);
  int ret = 0;
  {
    LockableGuard lock_guard(rwlock);
    ret = TryLockFunc(rwlock);
    if (ret == 0) {
      return 0;
    }
    if (queue.Contains(self)) {
      return EDEADLK;
    }
  }

  while (ret == EBUSY) {
    for (int i = 0; i < kNumSpinLockAttempts; i++) {
      {
        LockableGuard lock_guard(rwlock);
        ret = TryLockFunc(rwlock);
        if (ret == 0) {
          return 0;
        }
      }
    }
    {
      LockableGuard lock_guard(rwlock);
      queue.Enqueue(self);
    }
#ifdef _ASYLO_PTHREAD_RWLOCK_TRANSITIONAL_FLAG
    if (rwlock->_untrusted_wait_queue) {
      enc_untrusted_thread_wait(rwlock->_untrusted_wait_queue);
    }
#else
    enc_pause();
#endif
    {
      LockableGuard lock_guard(rwlock);
      queue.Remove(self);
    }
  }

  return ret;
}

void pthread_tsd_run_destructors() {
  struct __pthread_info *self =
      reinterpret_cast<struct __pthread_info *>(pthread_self());
  pthread_rwlock_rdlock(&key_lock);
  for (int i = 0; i < PTHREAD_KEYS_MAX; ++i) {
    void *val = self->tsd[i];
    void (*destructor)(void *) = tsd_destructors[i];
    self->tsd[i] = nullptr;
    if (val && destructor && destructor != NoDestructor) {
      destructor(val);
    }
  }
  pthread_rwlock_unlock(&key_lock);
}

struct start_args {
  void *(*start_func)(void *);
  void *start_arg;
};

int start(void *p) {
  struct start_args *args = reinterpret_cast<struct start_args *>(p);
  asylo::ThreadManager *const thread_manager =
      asylo::ThreadManager::GetInstance();
  thread_manager->UpdateThreadResult(pthread_self(),
                                     args->start_func(args->start_arg));
  pthread_tsd_run_destructors();
  return 0;
}

// Allocate thread specific data for the calling thread if it hasn't yet been
// allocated.
bool CheckAndAllocateThreadSpecificData() {
  auto self = reinterpret_cast<struct __pthread_info *>(pthread_self());
  // This can only happen in the main thread or the threads created by the host
  // entering the enclave.
  if (!self->tsd) {
    void *tsd = malloc(__pthread_tsd_size);
    if (tsd == MAP_FAILED) {
      return false;
    }
    memset(tsd, 0, __pthread_tsd_size);
    self->tsd = reinterpret_cast<void **>(tsd);
  }
  return true;
}

}  // namespace

namespace asylo {
namespace pthread_impl {

QueueOperations::QueueOperations(__pthread_list_t *list) : list_(list) {
  if (!list_) {
    abort();
  }
}

void QueueOperations::Dequeue() {
  if (!list_->_first) {
    return;
  }

  __pthread_list_node_t *old_first = list_->_first;
  list_->_first = old_first->_next;
  free_list_node(old_first);
}

pthread_t QueueOperations::Front() const {
  if (!list_->_first) {
    return PTHREAD_T_NULL;
  }
  return list_->_first->_thread_id;
}

void QueueOperations::Enqueue(const pthread_t id) {
  __pthread_list_node_t *last = alloc_list_node(id);

  if (!list_->_first) {
    list_->_first = last;
    return;
  }

  __pthread_list_node_t *current = list_->_first;
  while (current->_next) {
    current = current->_next;
  }
  current->_next = last;
}

bool QueueOperations::Remove(const pthread_t id) {
  __pthread_list_node_t *curr, *prev;

  for (curr = list_->_first, prev = nullptr; curr;
       prev = curr, curr = curr->_next) {
    if (curr->_thread_id == id) {
      if (!prev) {
        // Node to remove was the first item in the list. Change the list head.
        list_->_first = curr->_next;
      } else {
        // Set previous node's next to be the deleted node's next.
        prev->_next = curr->_next;
      }

      free_list_node(curr);
      return true;
    }
  }

  return false;
}

bool QueueOperations::Contains(const pthread_t id) const {
  __pthread_list_node_t *current = list_->_first;
  while (current) {
    if (current->_thread_id == id) {
      return true;
    }
    current = current->_next;
  }
  return false;
}

void QueueOperations::Clear() {
  while (!Empty()) {
    Dequeue();
  }
}

bool QueueOperations::Empty() const {
  const __pthread_list_node_t *current = list_->_first;
  return current == nullptr;
}

}  //  namespace pthread_impl
}  //  namespace asylo

extern "C" {

// Functions available via <pthread.h>

pthread_t pthread_self() {
  static_assert(sizeof(pthread_t) == sizeof(uint64_t) &&
                    (std::is_pointer<pthread_t>::value ||
                     std::is_integral<pthread_t>::value),
                "pthread_t must be a 64-bit integer or pointer type.");
  return static_cast<pthread_t>(enc_thread_self());
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
  // Store the __pthread_info and the start function in the TLS specified by
  // pthread library, so it can be accessed by other pthread functions.
  // The order is __pthread_info struct, then start function.
  size_t size = sizeof(struct __pthread_info) + sizeof(struct start_args) +
                __pthread_tsd_size;
  void *tls = mmap(/*addr=*/nullptr, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, /*fd=*/-1, /*offset=*/0);
  if (tls == MAP_FAILED) {
    return -1;
  }
  memset(tls, 0, size);
  auto thread_data = reinterpret_cast<struct __pthread_info *>(tls);
  thread_data->self = thread_data;
  thread_data->tls_size = size;
  pthread_attr_t pthread_attr = {0};
  if (attr) {
    pthread_attr = *attr;
    thread_data->attr = &pthread_attr;
  }

  struct start_args *args = reinterpret_cast<struct start_args *>(
      reinterpret_cast<uintptr_t>(tls) + sizeof(struct __pthread_info));
  args->start_func = start_routine;
  args->start_arg = arg;

  void *tsd = reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(tls) + size -
                                       __pthread_tsd_size);
  thread_data->tsd = reinterpret_cast<void **>(tsd);

  pid_t parent_tid;
  int ret = enclave_clone(start, /*stack=*/nullptr, CLONE_THREAD | CLONE_SETTLS,
                          args, &parent_tid, tls, /*child_tid=*/nullptr);
  if (thread) {
    *thread = thread_data->thread_id;
  }
  return ret;
}

int pthread_join(pthread_t thread, void **value_ptr) {
  asylo::ThreadManager *const thread_manager =
      asylo::ThreadManager::GetInstance();
  return thread_manager->JoinThread(thread, value_ptr);
}

int pthread_detach(pthread_t thread) {
  asylo::ThreadManager *const thread_manager =
      asylo::ThreadManager::GetInstance();
  return thread_manager->DetachThread(thread);
}

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *)) {
  if (!CheckAndAllocateThreadSpecificData()) {
    return -1;
  }
  if (!destructor) {
    destructor = NoDestructor;
  }
  pthread_rwlock_wrlock(&key_lock);
  for (pthread_key_t next_key = 0; next_key < PTHREAD_KEYS_MAX; ++next_key) {
    if (!tsd_destructors[next_key]) {
      tsd_destructors[next_key] = destructor;
      *key = next_key;
      pthread_rwlock_unlock(&key_lock);
      return 0;
    }
  }
  pthread_rwlock_unlock(&key_lock);
  return EAGAIN;
}

int pthread_key_delete(pthread_key_t key) {
  if (key > PTHREAD_KEYS_MAX) {
    return EINVAL;
  }
  pthread_rwlock_wrlock(&key_lock);
  tsd_destructors[key] = nullptr;
  pthread_rwlock_unlock(&key_lock);
  return 0;
}

void *pthread_getspecific(pthread_key_t key) {
  // Behavior if the key wasn't obtained through pthread_key_create is
  // undefined.
  if (key >= PTHREAD_KEYS_MAX) {
    return nullptr;
  }

  if (!CheckAndAllocateThreadSpecificData()) {
    return nullptr;
  }
  auto self = reinterpret_cast<struct __pthread_info *>(pthread_self());
  return self->tsd[key];
}

int pthread_setspecific(pthread_key_t key, const void *value) {
  // Behavior if the key wasn't obtained through pthread_key_create is
  // undefined.
  if (key >= PTHREAD_KEYS_MAX) {
    return EINVAL;
  }
  if (!CheckAndAllocateThreadSpecificData()) {
    return -1;
  }
  auto self = reinterpret_cast<struct __pthread_info *>(pthread_self());
  self->tsd[key] = const_cast<void *>(value);
  return 0;
}
// Initializes |mutex|, |attr| is unused.
int pthread_mutex_init(pthread_mutex_t *mutex,
                       const pthread_mutexattr_t *attr) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_mutex_t>(mutex)) {
    return EFAULT;
  }

  *mutex = PTHREAD_MUTEX_INITIALIZER;
  return 0;
}

// Destroys |mutex|, returns error if there are threads waiting on |mutex|.
int pthread_mutex_destroy(pthread_mutex_t *mutex) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_mutex_t>(mutex)) {
    return EFAULT;
  }

  LockableGuard lock_guard(mutex);
  asylo::pthread_impl::QueueOperations list(mutex);
  if (!list.Empty()) {
    return EBUSY;
  }

  return 0;
}

// Locks |mutex|.
int pthread_mutex_lock(pthread_mutex_t *mutex) {
  int ret = pthread_mutex_check_parameter(mutex);
  if (ret != 0) {
    return ret;
  }

  const pthread_t self = pthread_self();
  asylo::pthread_impl::QueueOperations list(mutex);

  if (!mutex->_untrusted_wait_queue) {
    LockableGuard lock_guard(mutex);
    // Ensure that the external wait queue is initialized
    initialize_wait_queue(&mutex->_untrusted_wait_queue);
  }

  while (true) {
    for (int i = 0; i < kNumSpinLockAttempts; i++) {
      {
        LockableGuard lock_guard(mutex);
        ret = pthread_mutex_lock_internal(mutex);
      }
      if (ret == 0) {
        return ret;
      }
    }
    // Sleep on an untrusted wait queue until woken up. Waiting will
    // be enabled if the lock is held, as the holder of the lock is
    // responsible for enabling and disabling waiting.
    if (mutex->_untrusted_wait_queue) {
      {
        LockableGuard lock_guard(mutex);
        list.Enqueue(self);
      }
      enc_untrusted_thread_wait(mutex->_untrusted_wait_queue);
      {
        LockableGuard lock_guard(mutex);
        list.Remove(self);
      }
    }
  }
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
  int ret = pthread_mutex_check_parameter(mutex);
  if (ret != 0) {
    return ret;
  }

  LockableGuard lock_guard(mutex);
  ret = pthread_mutex_lock_internal(mutex);
  return ret;
}

// Unlocks |mutex|.
int pthread_mutex_unlock(pthread_mutex_t *mutex) {
  int ret = pthread_mutex_check_parameter(mutex);
  if (ret != 0) {
    return ret;
  }

  asylo::pthread_impl::QueueOperations list(mutex);
  LockableGuard lock_guard(mutex);

  if (mutex->_owner == PTHREAD_T_NULL) {
    return EINVAL;
  }

  if (mutex->_owner != pthread_self()) {
    return EPERM;
  }

  mutex->_refcount--;
  // If we change state from locked to unlocked
  if (mutex->_refcount == 0) {
    mutex->_owner = PTHREAD_T_NULL;
    if (mutex->_untrusted_wait_queue) {
      enc_untrusted_disable_waiting(mutex->_untrusted_wait_queue);
      // Only notify if there is a thread to notify
      if (!list.Empty()) {
        enc_untrusted_notify(mutex->_untrusted_wait_queue);
      }
    }
  }

  return 0;
}

// Runs the given |init_routine| exactly once.
int pthread_once(pthread_once_t *once, void (*init_routine)(void)) {
  asylo::pthread_impl::PthreadMutexLock lock(&once->_mutex);
  if (!once->_ran) {
    init_routine();
    once->_ran = true;
  }
  return 0;
}

// Initializes |cond|, |attr| is unused.
int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_cond_t>(cond)) {
    return EFAULT;
  }

  *cond = PTHREAD_COND_INITIALIZER;
  return 0;
}

// Destroys |cond|, errors if there are threads waiting on |cond|.
int pthread_cond_destroy(pthread_cond_t *cond) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_cond_t>(cond)) {
    return EFAULT;
  }

  return 0;
}

// Blocks until the given |cond| is signaled or broadcasted, or a timeout
// occurs. |mutex| must be locked before calling and will be locked on return.
// Returns ETIMEDOUT if |deadline| (which is an absolute time) is not null, the
// current time is later than |deadline|, and |cond| has not yet been signaled
// or broadcasted.
//
// Warning: Enclaves do not currently have a source of secure time. A hostile
// host could cause this function to either return ETIMEDOUT immediately or
// never time out, acting like pthread_cond_wait().
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                           const struct timespec *deadline) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_cond_t>(cond) ||
      !asylo::primitives::IsValidEnclaveAddress<pthread_mutex_t>(mutex)) {
    return EFAULT;
  }

  // If a deadline has been specified, ensure it is valid.
  if (deadline &&
      !asylo::primitives::IsValidEnclaveAddress<timespec>(deadline)) {
    return EFAULT;
  }

  // Get the current thread ID to use as a wait queue value, truncated
  // to 32 bits to fit in the wait queue state.
  const pthread_t self = pthread_self();

#ifdef _ASYLO_PTHREAD_COND_TRANSITIONAL_FLAG
  // Use a global atomic counter to enumerate each thread. This generates a
  // thread-specific 32 bit unique identifier for each thread, which is not the
  // address of anything, and thus safer to expose outside the enclave (relative
  // to some implementations of pthread_self()).
  static std::atomic<int32_t> thread_counter(1);
  thread_local int32_t self_32 =
      thread_counter.fetch_add(1, std::memory_order_relaxed);

  if (!cond->_untrusted_wait_queue) {
    // initialize wait queue
    LockableGuard lock_guard(cond);
    initialize_wait_queue(&cond->_untrusted_wait_queue);
  }
#endif

  asylo::pthread_impl::QueueOperations list(cond);
  // Store a thread-specific unique ID to the wait queue. This allows wait to be
  // atomic, as any other thread signalling a wakeup will overwrite this value
  // with a different thread unique ID, disabling this thread from sleeping.
  {
    LockableGuard lock_guard(cond);
#ifdef _ASYLO_PTHREAD_COND_TRANSITIONAL_FLAG
    if (cond->_untrusted_wait_queue) {
      enc_untrusted_wait_queue_set_value(cond->_untrusted_wait_queue, self_32);
    }
#endif
    list.Enqueue(self);
  }

  int ret = pthread_mutex_unlock(mutex);
  if (ret != 0) {
    return ret;
  }

#ifdef _ASYLO_PTHREAD_COND_TRANSITIONAL_FLAG
  // A wait for 0 microseconds will actually wait indefinitely.
  uint64_t time_left_micros = 0;
  if (deadline) {
    timespec curr_time;
    ret = clock_gettime(CLOCK_REALTIME, &curr_time);
    if (ret != 0) {
      pthread_mutex_lock(mutex);
      return ret;
    }

    // TimeSpecSubtract returns true if deadline < curr_time.
    timespec time_left;
    if (asylo::TimeSpecSubtract(*deadline, curr_time, &time_left)) {
      pthread_mutex_lock(mutex);
      return ETIMEDOUT;
    }
    time_left_micros = asylo::TimeSpecToMicroseconds(&time_left);

    // Timeout if we're exactly at the deadline. Otherwise we'd sleep for 0
    // microseconds, which is an indefinite sleep.
    if (time_left_micros == 0) {
      pthread_mutex_lock(mutex);
      return ETIMEDOUT;
    }
  }
  // Sleep on the wait queue until either the timeout occurs, or a wakeup
  // occurs.
  if (cond->_untrusted_wait_queue) {
    enc_untrusted_thread_wait_value(cond->_untrusted_wait_queue, self_32,
                                    time_left_micros);
  }
  {
    LockableGuard lock_guard(cond);
    list.Remove(self);
  }

  if (deadline) {
    // Check if awoken up due to timeout.
    timespec curr_time;
    ret = clock_gettime(CLOCK_REALTIME, &curr_time);
    if (ret != 0) {
      pthread_mutex_lock(mutex);
      return ret;
    }

    // TimeSpecSubtract returns true if deadline < curr_time.
    timespec time_left;
    if (asylo::TimeSpecSubtract(*deadline, curr_time, &time_left)) {
      pthread_mutex_lock(mutex);
      return ETIMEDOUT;
    }
  }

  return pthread_mutex_lock(mutex);
#else
  while (true) {
    enc_untrusted_sched_yield();

    // If a deadline has been specified, check to see if it has passed.
    if (deadline) {
      timespec curr_time;
      ret = clock_gettime(CLOCK_REALTIME, &curr_time);
      if (ret != 0) {
        break;
      }

      // TimeSpecSubtract returns true if deadline < curr_time.
      timespec time_left;
      if (asylo::TimeSpecSubtract(*deadline, curr_time, &time_left)) {
        ret = ETIMEDOUT;
        break;
      }
    }

    LockableGuard lock_guard(cond);
    if (!list.Contains(self)) {
      break;
    }
  }

  {
    LockableGuard lock_guard(cond);
    list.Remove(self);
  }

  // Only set the retval to be the result of re-locking the mutex if there isn't
  // already another error we're trying to return. Otherwise, we give preference
  // to returning the pre-existing error and drop the error caused by re-locking
  // the mutex.
  int relock_ret = pthread_mutex_lock(mutex);
  if (ret != 0) {
    return ret;
  }
  return relock_ret;
#endif
}

// Blocks until the given |cond| is signaled or broadcasted. |mutex| must  be
// locked before calling and will be locked on return.
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
  return pthread_cond_timedwait(cond, mutex, nullptr);
}

int pthread_condattr_init(pthread_condattr_t *attr) { return 0; }

int pthread_condattr_destroy(pthread_condattr_t *attr) { return 0; }

// Wakes |num_threads| waiting on |cond|.
int pthread_cond_notify_internal(pthread_cond_t *cond, int num_threads) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_cond_t>(cond)) {
    return EFAULT;
  }

#ifdef _ASYLO_PTHREAD_COND_TRANSITIONAL_FLAG
  // If there is no queue, there is no way for other threads to be asleep on
  // that queue, and thus there is nothing to do.
  if (cond->_untrusted_wait_queue != nullptr) {
    asylo::pthread_impl::QueueOperations list(cond);
    const int32_t self = static_cast<int32_t>(pthread_self());
    LockableGuard lock_guard(cond);
    enc_untrusted_wait_queue_set_value(cond->_untrusted_wait_queue, self);
    if (!list.Empty()) {
      enc_untrusted_notify(cond->_untrusted_wait_queue, num_threads);
    }
  }
#else
  LockableGuard lock_guard(cond);
  asylo::pthread_impl::QueueOperations list(cond);
  if (num_threads == 1 && !list.Empty()) {
    list.Dequeue();
  } else {
    // only called with 1 and INT_MAX
    list.Clear();
  }
#endif
  return 0;
}

// Wakes the first waiting thread on |cond|.
int pthread_cond_signal(pthread_cond_t *cond) {
  return pthread_cond_notify_internal(cond, 1);
}

// Wakes all the waiting threads on |cond|.
int pthread_cond_broadcast(pthread_cond_t *cond) {
  return pthread_cond_notify_internal(cond, INT_MAX);
}

// Initialize |sem| with an initial semaphore value of |value|. |pshared| must
// be 0; shared semaphores are not supported.
int sem_init(sem_t *sem, const int pshared, const unsigned int value) {
  if (!asylo::primitives::IsValidEnclaveAddress<sem_t>(sem)) {
    return ConvertToErrno(EFAULT);
  }

  // We only support inside-an-enclave semaphores, not cross-process semaphores.
  if (pshared) {
    return ConvertToErrno(ENOSYS);
  }

  sem->count_ = value;

  int ret = pthread_mutex_init(&sem->mu_, nullptr);
  if (ret != 0) {
    return ConvertToErrno(ret);
  }

  ret = pthread_cond_init(&sem->cv_, nullptr);
  if (ret != 0) {
    return ConvertToErrno(ret);
  }

  return 0;
}

// Get the current value of |sem| and write it to |sval|.
int sem_getvalue(sem_t *sem, int *sval) {
  if (!asylo::primitives::IsValidEnclaveAddress<sem_t>(sem) ||
      !asylo::primitives::IsValidEnclaveAddress<int>(sval)) {
    return ConvertToErrno(EFAULT);
  }

  asylo::pthread_impl::PthreadMutexLock lock(&sem->mu_);
  *sval = sem->count_;
  return 0;
}

// Unlock |sem|, unblocking a thread that might be waiting for it.
int sem_post(sem_t *sem) {
  if (!asylo::primitives::IsValidEnclaveAddress<sem_t>(sem)) {
    return ConvertToErrno(EFAULT);
  }

  asylo::pthread_impl::PthreadMutexLock lock(&sem->mu_);
  sem->count_++;
  return ConvertToErrno(pthread_cond_signal(&sem->cv_));
}

// Wait for |sem| to be unlocked until the time specified by |abs_timeout|. If
// |abs_timeout| is null, waits indefinitely. Returns 0 if the semaphore has
// been unlocked. Returns -1 on err. errno will be set to ETIMEDOUT if the
// failure is due to a timeout.
int sem_timedwait(sem_t *sem, const timespec *abs_timeout) {
  if (!asylo::primitives::IsValidEnclaveAddress<sem_t>(sem)) {
    return ConvertToErrno(EFAULT);
  }

  if (abs_timeout &&
      !asylo::primitives::IsValidEnclaveAddress<timespec>(abs_timeout)) {
    return ConvertToErrno(EFAULT);
  }

  asylo::pthread_impl::PthreadMutexLock lock(&sem->mu_);

  int ret = 0;
  while (sem->count_ == 0) {
    ret = pthread_cond_timedwait(&sem->cv_, &sem->mu_, abs_timeout);

    if (ret != 0) {
      break;
    }
  }

  // If the pthread_cond_timedwait succeeds, reduce the semaphore count by one,
  // unlock the mutex, and return any error that might arise from the unlocking.
  if (ret == 0) {
    sem->count_--;
    return 0;
  }

  // pthread_cond_timedwait failed. We don't decrease the semaphore value and
  // return whatever retval came from pthread_cond_timedwait.
  return ConvertToErrno(ret);
}

// Wait indefinitely for |sem| to be unlocked.
int sem_wait(sem_t *sem) { return sem_timedwait(sem, nullptr); }

int sem_trywait(sem_t *sem) {
  struct timespec deadline = {0, 0};
  int ret = sem_timedwait(sem, &deadline);
  if (ret != 0 && errno == ETIMEDOUT) {
    errno = EAGAIN;
  }

  return ret;
}

int sem_destroy(sem_t *sem) {
  if (!asylo::primitives::IsValidEnclaveAddress<sem_t>(sem)) {
    return ConvertToErrno(EFAULT);
  }

  int ret = pthread_cond_destroy(&sem->cv_);
  if (ret != 0) {
    return ConvertToErrno(ret);
  }

  ret = pthread_mutex_destroy(&sem->mu_);
  if (ret != 0) {
    return ConvertToErrno(ret);
  }

  return 0;
}

int pthread_rwlock_init(pthread_rwlock_t *rwlock,
                        const pthread_rwlockattr_t *attr) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_rwlock_t>(rwlock)) {
    return ConvertToErrno(EFAULT);
  }

  *rwlock = PTHREAD_RWLOCK_INITIALIZER;

  return 0;
}

int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_rwlock_t>(rwlock)) {
    return ConvertToErrno(EFAULT);
  }

  LockableGuard lock_guard(rwlock);
  return pthread_rwlock_tryrdlock_internal(rwlock);
}

int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_rwlock_t>(rwlock)) {
    return ConvertToErrno(EFAULT);
  }

  LockableGuard lock_guard(rwlock);
  return pthread_rwlock_trywrlock_internal(rwlock);
}

int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock) {
  return pthread_rwlock_lock<pthread_rwlock_tryrdlock_internal>(rwlock);
}

int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock) {
  return pthread_rwlock_lock<pthread_rwlock_trywrlock_internal>(rwlock);
}

int pthread_rwlock_unlock(pthread_rwlock_t *rwlock) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_rwlock_t>(rwlock)) {
    return ConvertToErrno(EFAULT);
  }

  asylo::pthread_impl::QueueOperations list(rwlock);
  LockableGuard lock_guard(rwlock);

  const pthread_t self = pthread_self();
  if (rwlock->_write_owner == self) {
    rwlock->_write_owner = PTHREAD_T_NULL;
#ifdef _ASYLO_PTHREAD_RWLOCK_TRANSITIONAL_FLAG
    if (rwlock->_untrusted_wait_queue) {
      enc_untrusted_disable_waiting(rwlock->_untrusted_wait_queue);
      if (!list.Empty()) {
        enc_untrusted_notify(rwlock->_untrusted_wait_queue);
      }
    }
#endif
    return 0;
  }

  rwlock->_reader_count--;
#ifdef _ASYLO_PTHREAD_RWLOCK_TRANSITIONAL_FLAG
  if (rwlock->_reader_count == 0 && rwlock->_untrusted_wait_queue) {
    enc_untrusted_disable_waiting(rwlock->_untrusted_wait_queue);
    if (!list.Empty()) {
      enc_untrusted_notify(rwlock->_untrusted_wait_queue);
    }
  }
#endif
  return 0;
}

int pthread_rwlock_destroy(pthread_rwlock_t *rwlock) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_rwlock_t>(rwlock)) {
    return ConvertToErrno(EFAULT);
  }

  LockableGuard lock_guard(rwlock);
  asylo::pthread_impl::QueueOperations queue(rwlock);
  if (rwlock->_write_owner == PTHREAD_T_NULL && queue.Empty()) {
    return 0;
  }

  return EBUSY;
}

int pthread_equal(pthread_t thread_one, pthread_t thread_two) {
  if (thread_one == thread_two) {
    return -1;
  }
  return 0;
}

void _pthread_cleanup_push(struct _pthread_cleanup_context *context,
                           void (*routine)(void *), void *arg) {
  asylo::ThreadManager *const thread_manager =
      asylo::ThreadManager::GetInstance();
  thread_manager->PushCleanupRoutine(std::bind(routine, arg));
}

void _pthread_cleanup_pop(struct _pthread_cleanup_context *context,
                          int execute) {
  asylo::ThreadManager *const thread_manager =
      asylo::ThreadManager::GetInstance();
  thread_manager->PopCleanupRoutine(execute != 0);
}

int pthread_mutexattr_init(pthread_mutexattr_t *mutexattr) { return 0; }
int pthread_mutexattr_destroy(pthread_mutexattr_t *mutexattr) { return 0; }
int pthread_mutexattr_settype(pthread_mutexattr_t *mutexattr, int type) {
  return 0;
}

int pthread_attr_init(pthread_attr_t *attr) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_attr_t>(attr)) {
    return ConvertToErrno(EFAULT);
  }

  attr->detach_state = PTHREAD_CREATE_JOINABLE;
  return 0;
}

int pthread_attr_destroy(pthread_attr_t *attr) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_attr_t>(attr)) {
    return ConvertToErrno(EFAULT);
  }
  return 0;
}

int pthread_attr_setdetachstate(pthread_attr_t *attr, int type) {
  if (!asylo::primitives::IsValidEnclaveAddress<pthread_attr_t>(attr)) {
    return ConvertToErrno(EFAULT);
  }

  if (type != PTHREAD_CREATE_JOINABLE && type != PTHREAD_CREATE_DETACHED) {
    return EINVAL;
  }

  attr->detach_state = type;
  return 0;
}

int pthread_attr_getschedpolicy(const pthread_attr_t *attr, int *policy) {
  return ENOSYS;
}
int pthread_attr_setschedpolicy(pthread_attr_t *attr, int policy) {
  return ENOSYS;
}
int pthread_attr_getscope(const pthread_attr_t *attr, int *scope) {
  return ENOSYS;
}
int pthread_attr_setscope(pthread_attr_t *attr, int scope) { return ENOSYS; }
int pthread_attr_getschedparam(const pthread_attr_t *attr,
                               struct sched_param *param) {
  return ENOSYS;
}
int pthread_attr_setschedparam(pthread_attr_t *attr,
                               const struct sched_param *param) {
  return ENOSYS;
}
int pthread_attr_getstacksize(const pthread_attr_t *attr, size_t *stacksize) {
  return ENOSYS;
}
int pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize) {
  return ENOSYS;
}

int pthread_cancel(pthread_t unused) { return ENOSYS; }
int pthread_setcancelstate(int state, int *oldstate) { return ENOSYS; }
int pthread_setcanceltype(int type, int *oldtype) { return ENOSYS; }

}  // extern "C"
