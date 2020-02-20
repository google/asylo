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

#ifndef ASYLO_UTIL_MUTEX_GUARDED_H_
#define ASYLO_UTIL_MUTEX_GUARDED_H_

#include <cassert>
#include <functional>
#include <type_traits>
#include <utility>

#include "absl/base/const_init.h"
#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"

namespace asylo {

template <typename T>
class LockView;

template <typename T>
class ReaderLockView;

// MutexGuarded<T> protects an object of type T with a mutex. MutexGuarded<T>
// does not allow direct access to the contained object. Instead, the mutex must
// be locked with an appropriate locking function that returns an object that
// can be dereferenced to access the contained T object.
//
// In general, it is unsafe to save a reference or pointer to the contained
// object or to one of its subcomponents (like a pointee or member).
//
// Example of common use:
//
//     // Initialize a mutex-guarded vector of numbers.
//     MutexGuarded<std::vector<int>> numbers(std::vector<int>());
//
//     // Spawn 10 threads that each push a number to the back of the vector.
//     std::vector<std::thread> threads;
//     for (int i = 0; i < 10; ++i) {
//       threads.emplace_back([i, &numbers] {
//         // Lock |numbers| to obtain a writeable view of the vector.
//         LockView<int> writeable_view = numbers.Lock();
//
//         // The |writeable_view| object dereferences to the contained vector.
//         writeable_view->push_back(i);
//
//         // The |writeable_view| object falls out of scope and unlocks the
//         // mutex here.
//       });
//     }
//
//     // The vector has been expanded a thread-safe manner.
//     auto readable_view = counter.ReaderLock();
//     CHECK_EQ(readable_view->size(), 10);
//
// WARNING: As stated above, in general, it is not thread-safe to save a
// reference or pointer to the contained object or one of its subcomponents
// and use it to access the object after the lock has gone out of scope:
//
//     MutexGuarded<std::unique_ptr<int>> counter(absl::make_unique<int>(0));
//
//     std::vector<std::thread> threads;
//     for (int i = 0; i < 10; ++i) {
//       threads.emplace_back([&counter] {
//         int *ptr_to_counter;
//
//         {
//           auto writeable_view = counter.Lock();
//
//           // CODE SMELL: a reference to the contained object is saved.
//           ptr_to_counter = writeable_view->get();
//         }
//
//         // UNSAFE: The contained object is accessed after the lock object has
//         // fallen out of scope.
//         ++*ptr_to_counter;
//       });
//     }
//
// It is safe to dereference a locked view object in the same statement in which
// it is created. This allows a single statement to acquire a lock and access
// the protected object:
//
//     MutexGuarded<std::vector<int>> numbers(std::vector<int>());
//
//     std::vector<std::thread> threads;
//     for (int i = 0; i < 10; ++i) {
//       threads.emplace_back([i, &numbers] {
//         numbers.Lock()->push_back(i);
//       });
//     }
//
//     CHECK_EQ(numbers.ReaderLock()->size(), 10);
//
// MutexGuarded<T> uses absl::Mutex for its internal mutex. MutexGuarded<T>
// exposes a similar API to absl::Mutex with the exception of methods related to
// unlocking. In general:
//
//   * For each of Lock() and ReaderLock(), MutexGuarded<T> contains a method of
//     the same name that returns an appropriate locked view object.
//
//   * For each of TryLock() and ReaderTryLock(), MutexGuarded<T> contains a
//     method of the same name that returns an absl::optional locked view
//     object. If the returned optional has a value, then the locking succeeded;
//     otherwise, the locking failed.
//
//   * For each of AssertHeld() and AssertReaderHeld(), MutexGuarded<T> contains
//     a method of the same name with identical semantics.
//
//   * For each of LockWhen() and ReaderLockWhen(), MutexGuarded<T> contains a
//     method of the same name that returns an appropriate locked view object.
//     Also see the note below about conditions.
//
//   * For each of LockWhenWithTimeout(), ReaderLockWhenWithTimeout(),
//     LockWhenWithDeadline(), and ReaderLockWhenWithDeadline(), MutexGuarded<T>
//     contains a method of the same name that returns std::pair of a bool and
//     an appropriate locked view object. The bool has the same semantics as the
//     return value of the corresponding method on absl::Mutex, and the locked
//     view object indicates the appropriate lock.
//
//     Also see the note below about conditions.
//
//   * MutexGuarded<T> does not directly expose Await(), AwaitWithTimeout(), or
//     AwaitWithDeadline() methods. Instead, these are provided on the locked
//     view objects.
//
// In all cases, the locking semantics remain the same, except that unlocking is
// accomplished through RAII on the returned object.
//
// MutexGuarded<T> does not expose Unlock() or ReaderUnlock() methods, since all
// unlocking is accoplished with RAII.
//
// MutexGuarded<T> does not expose "Writer"-named aliases for its exclusive
// locking methods.
//
// The conditions passed to MutexGuarded<T>'s LockWhen() methods and the Await()
// methods on the locked view objects have type std::function<bool(const T &)>,
// rather than absl::Condition. The const T & argument in these functions is a
// reference to the object guarded by a MutexGuarded<T>.
template <typename T>
class MutexGuarded {
  static_assert(std::is_move_constructible<T>::value,
                "T must be a move-constructible type");

 public:
  MutexGuarded() = default;

  // Constucts a MutexGuarded<T> that initially holds |value|.
  explicit MutexGuarded(T value) : value_(std::forward<T>(value)) {}

  // Like the constructor above, but creates the mutex with static storage
  // duration.
  MutexGuarded(T value, absl::ConstInitType const_init)
      : mu_(const_init), value_(std::forward<T>(value)) {}

  MutexGuarded(const MutexGuarded &other) = delete;
  MutexGuarded &operator=(const MutexGuarded &other) = delete;

  // MutexGuarded<T> objects can be moved. However, moving a MutexGuarded<T>
  // object while there are locked view objects referencing it is unsafe and
  // will cause undefined behavior.

  // Move constructor for MutexGuarded<T>. Does not move the mutex from |other|
  // into *this. Locks |other| before moving.
  MutexGuarded(MutexGuarded &&other) : value_(other.Release()) {}

  // Move assignment operator for MutexGuarded<T>. Does not move the mutex from
  // |other| into *this. Locks *this and |other| before moving.
  MutexGuarded &operator=(MutexGuarded &&other) ABSL_LOCKS_EXCLUDED(mu_) {
    absl::MutexLock lock(&mu_);
    value_ = other.Release();
    return *this;
  }

  // Releases ownership of the contained value to the caller. Exclusively locks
  // the contained mutex before doing so.
  T &&Release() ABSL_LOCKS_EXCLUDED(mu_) {
    absl::MutexLock lock(&mu_);
    return std::move(value_);
  }

  // Returns a smart pointer to the contained value. The smart pointer is also
  // an RAII writer lock on the contained mutex.
  LockView<T> Lock() ABSL_LOCKS_EXCLUDED(mu_) {
    mu_.Lock();
    return LockView<T>(&mu_, &value_);
  }

  // Returns a read-only smart pointer to the contained value. The smart pointer
  // is also an RAII reader lock on the contained mutex.
  ReaderLockView<T> ReaderLock() const ABSL_LOCKS_EXCLUDED(mu_) {
    mu_.ReaderLock();
    return ReaderLockView<T>(&mu_, &value_);
  }

  // Tries to acquire the contained mutex exclusively. If successful, behaves as
  // Lock(). Otherwise, returns absl::nullopt.
  absl::optional<LockView<T>> TryLock() ABSL_LOCKS_EXCLUDED(mu_) {
    if (mu_.TryLock()) {
      return LockView<T>(&mu_, &value_);
    } else {
      return absl::nullopt;
    }
  }

  // Tries to acquire a shared lock on the contained mutex. If successful,
  // behaves as ReaderLock(). Otherwise, returns absl::nullopt.
  absl::optional<ReaderLockView<T>> ReaderTryLock() const
      ABSL_LOCKS_EXCLUDED(mu_) {
    if (mu_.ReaderTryLock()) {
      return ReaderLockView<T>(&mu_, &value_);
    } else {
      return absl::nullopt;
    }
  }

  // Asserts that the current thread holds an exclusive (writer) lock on the
  // contained mutex. If it does not, then behaves as absl::Mutex::AssertHeld().
  void AssertHeld() const { mu_.AssertHeld(); }

  // Asserts that the current thread holds a shared (reader) lock on the
  // contained mutex. If it does not, then behaves as
  // absl::Mutex::AssertReaderHeld().
  void AssertReaderHeld() const { mu_.AssertReaderHeld(); }

  // Returns a smart pointer to the contained value once |cond| is true and the
  // contained mutex can be acquired exclusively. The smart pointer is also an
  // RAII writer lock on the contained mutex.
  LockView<T> LockWhen(std::function<bool(const T &)> cond)
      ABSL_LOCKS_EXCLUDED(mu_) {
    auto condition_function = [this, cond] { return cond(value_); };
    mu_.LockWhen(absl::Condition(&condition_function));
    return LockView<T>(&mu_, &value_);
  }

  // Returns a smart pointer to the contained value once |cond| is true and the
  // contained mutex can be acquired in shared mode. The smart pointer is also
  // an RAII reader lock on the contained mutex.
  ReaderLockView<T> ReaderLockWhen(std::function<bool(const T &)> cond) const
      ABSL_LOCKS_EXCLUDED(mu_) {
    auto condition_function = [this, cond] { return cond(value_); };
    mu_.ReaderLockWhen(absl::Condition(&condition_function));
    return ReaderLockView<T>(&mu_, &value_);
  }

  // Returns a bool and a smart pointer to the contained value once the
  // contained mutex can be acquired exclusively and either:
  //
  //  * |cond| is true; or
  //  * |timeout| has passed since LockWhenWithTimeout() was called.
  //
  // The bool member of the pair is true if and only if |cond| was true when the
  // mutex was acquired.
  //
  // The returned smart pointer is also an RAII writer lock on the contained
  // mutex.
  std::pair<bool, LockView<T>> LockWhenWithTimeout(
      std::function<bool(const T &)> cond, absl::Duration timeout)
      ABSL_LOCKS_EXCLUDED(mu_) {
    auto condition_function = [this, cond] { return cond(value_); };
    bool cond_is_true =
        mu_.LockWhenWithTimeout(absl::Condition(&condition_function), timeout);
    return std::make_pair(cond_is_true, LockView<T>(&mu_, &value_));
  }

  // Returns a bool and a smart pointer to the contained value once the
  // contained mutex can be acquired in shared mode and either:
  //
  //  * |cond| is true; or
  //  * |timeout| has passed since ReaderLockWhenWithTimeout() was called.
  //
  // The bool member of the pair is true if and only if |cond| was true when the
  // mutex was acquired.
  //
  // The returned smart pointer is also an RAII reader lock on the contained
  // mutex.
  std::pair<bool, ReaderLockView<T>> ReaderLockWhenWithTimeout(
      std::function<bool(const T &)> cond, absl::Duration timeout) const
      ABSL_LOCKS_EXCLUDED(mu_) {
    auto condition_function = [this, cond] { return cond(value_); };
    bool cond_is_true = mu_.ReaderLockWhenWithTimeout(
        absl::Condition(&condition_function), timeout);
    return std::make_pair(cond_is_true, ReaderLockView<T>(&mu_, &value_));
  }

  // As LockWhenWithTimeout(), but uses a deadline instead of a timeout.
  std::pair<bool, LockView<T>> LockWhenWithDeadline(
      std::function<bool(const T &)> cond, absl::Time deadline)
      ABSL_LOCKS_EXCLUDED(mu_) {
    auto condition_function = [this, cond] { return cond(value_); };
    bool cond_is_true = mu_.LockWhenWithDeadline(
        absl::Condition(&condition_function), deadline);
    return std::make_pair(cond_is_true, LockView<T>(&mu_, &value_));
  }

  // As ReaderLockWhenWithTimeout(), but uses a deadline instead of a timeout.
  std::pair<bool, ReaderLockView<T>> ReaderLockWhenWithDeadline(
      std::function<bool(const T &)> cond, absl::Time deadline) const
      ABSL_LOCKS_EXCLUDED(mu_) {
    auto condition_function = [this, cond] { return cond(value_); };
    bool cond_is_true = mu_.ReaderLockWhenWithDeadline(
        absl::Condition(&condition_function), deadline);
    return std::make_pair(cond_is_true, ReaderLockView<T>(&mu_, &value_));
  }

 private:
  mutable absl::Mutex mu_;
  T value_ ABSL_GUARDED_BY(mu_);
};

// A writeable view of a mutex-guarded object of type T. The view object
// maintains a writer lock on the guarding mutex during its lifetime. The view
// object can be dereferenced to the guarded object.
template <typename T>
class LockView {
 public:
  LockView() = delete;

  LockView(const LockView &other) = delete;
  LockView &operator=(const LockView &other) = delete;

  // Non-default move operations are provided because default move
  // implementations do not set moved-from raw pointers to nullptr. The default
  // move-assignment implementation also leaves the previously held mutex (if
  // any) locked.

  LockView(LockView &&other) : mu_(other.mu_), value_(other.value_) {
    other.Clear();
  }

  LockView &operator=(LockView &&other) {
    if (&other != this) {
      // Ensure that the current mutex, if any, is released before moving.
      if (mu_ != nullptr) {
        mu_->WriterUnlock();
      }

      mu_ = other.mu_;
      value_ = other.value_;

      other.Clear();
    }
    return *this;
  }

  ~LockView() {
    if (mu_ != nullptr) {
      mu_->WriterUnlock();
    }
  }

  T &operator*() { return *value_; }

  T *operator->() { return value_; }

  // Releases the lock on the referened mutex and reacquires it when |cond| is
  // true and the mutex can be acquired exclusively again.
  void Await(std::function<bool(const T &)> cond) {
    auto condition_function = [this, cond] { return cond(*value_); };
    mu_->Await(absl::Condition(&condition_function));
  }

  // Releases the lock on the referened mutex and reacquires it when the mutex
  // can be reacquired exclusively and either:
  //
  //  * |cond| evaluates to true when passed the guarded value; or
  //  * |timeout| has passed since AwaitWithTimeout() was called.
  //
  // The returned bool indicates whether |cond| was true when the mutex was
  // reacquired.
  bool AwaitWithTimeout(std::function<bool(const T &)> cond,
                        absl::Duration timeout) {
    auto condition_function = [this, cond] { return cond(*value_); };
    return mu_->AwaitWithTimeout(absl::Condition(&condition_function), timeout);
  }

  // As AwaitWithTimeout(), but uses a deadline instead of a timeout.
  bool AwaitWithDeadline(std::function<bool(const T &)> cond,
                         absl::Time deadline) {
    auto condition_function = [this, cond] { return cond(*value_); };
    return mu_->AwaitWithDeadline(absl::Condition(&condition_function),
                                  deadline);
  }

 protected:
  template <typename U>
  friend class MutexGuarded;

  LockView(absl::Mutex *mu, T *value) : mu_(mu), value_(value) {}

 private:
  // Sets all internal pointers to nullptr.
  void Clear() {
    mu_ = nullptr;
    value_ = nullptr;
  }

  absl::Mutex *mu_;
  T *value_;
};

// A read-only view of a mutex-guarded object of type T. The view object
// maintains a reader lock on the guarding mutex during its lifetime. The view
// object dereferences to the guarded object.
template <typename T>
class ReaderLockView {
 public:
  ReaderLockView() = delete;

  ReaderLockView(const ReaderLockView &other) = delete;
  ReaderLockView &operator=(const ReaderLockView &other) = delete;

  // Non-default move operations are provided because default move
  // implementations do not set moved-from raw pointers to nullptr. The default
  // move-assignment implementation also leaves the previously held mutex (if
  // any) locked.

  ReaderLockView(ReaderLockView &&other)
      : mu_(other.mu_), value_(other.value_) {
    other.Clear();
  }

  ReaderLockView &operator=(ReaderLockView &&other) {
    if (&other != this) {
      // Ensure that the current mutex, if any, is released before moving.
      if (mu_ != nullptr) {
        mu_->ReaderUnlock();
      }

      mu_ = other.mu_;
      value_ = other.value_;

      other.Clear();
    }
    return *this;
  }

  ~ReaderLockView() {
    if (mu_ != nullptr) {
      mu_->ReaderUnlock();
    }
  }

  const T &operator*() const { return *value_; }

  const T *operator->() const { return value_; }

  // Releases the lock on the referened mutex and reacquires it when |cond| is
  // true and the mutex can be acquired in shared mode again.
  void Await(std::function<bool(const T &)> cond) {
    auto condition_function = [this, cond] { return cond(*value_); };
    mu_->Await(absl::Condition(&condition_function));
  }

  // Releases the lock on the referened mutex and reacquires it when the mutex
  // can be reacquired in shared mode and either:
  //
  //  * |cond| evaluates to true when passed the guarded value; or
  //  * |timeout| has passed since AwaitWithTimeout() was called.
  //
  // The returned bool indicates whether |cond| was true when the mutex was
  // reacquired.
  bool AwaitWithTimeout(std::function<bool(const T &)> cond,
                        absl::Duration timeout) {
    auto condition_function = [this, cond] { return cond(*value_); };
    return mu_->AwaitWithTimeout(absl::Condition(&condition_function), timeout);
  }

  // As AwaitWithTimeout(), but uses a deadline instead of a timeout.
  bool AwaitWithDeadline(std::function<bool(const T &)> cond,
                         absl::Time deadline) {
    auto condition_function = [this, cond] { return cond(*value_); };
    return mu_->AwaitWithDeadline(absl::Condition(&condition_function),
                                  deadline);
  }

 protected:
  template <typename U>
  friend class MutexGuarded;

  ReaderLockView(absl::Mutex *mu, const T *value) : mu_(mu), value_(value) {}

 private:
  // Sets all internal pointers to nullptr.
  void Clear() {
    mu_ = nullptr;
    value_ = nullptr;
  }

  absl::Mutex *mu_;
  const T *value_;
};

}  // namespace asylo

#endif  // ASYLO_UTIL_MUTEX_GUARDED_H_
