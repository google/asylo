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

#include "asylo/platform/posix/threading/thread_manager.h"

#include <algorithm>
#include <cstdlib>
#include <memory>

#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/platform/core/trusted_global_state.h"

namespace asylo {

ThreadManager::Thread::Thread() {
  this->lock = PTHREAD_MUTEX_INITIALIZER;
  this->state_change_cond = PTHREAD_COND_INITIALIZER;
}

int ThreadManager::Thread::UpdateThreadState(const pthread_t thread_id,
                                             const ThreadState state) {
  int ret = pthread_mutex_lock(&this->lock);
  if (ret != 0) {
    return ret;
  }
  this->state = state;
  this->thread_id = thread_id;
  ret = pthread_cond_broadcast(&this->state_change_cond);
  if (ret != 0) {
    return ret;
  }
  return pthread_mutex_unlock(&this->lock);
}

ThreadManager::ThreadManager() {
  this->threads_lock_ = PTHREAD_MUTEX_INITIALIZER;
  this->scheduled_lock_ = PTHREAD_MUTEX_INITIALIZER;
}

ThreadManager *ThreadManager::GetInstance() {
  static ThreadManager *instance = new ThreadManager();
  return instance;
}

std::shared_ptr<ThreadManager::Thread> ThreadManager::QueueThread(
    const std::function<void *(void *)> &function, void *const arg) {
  LockQueuedThreads();
  queued_threads_.emplace(std::make_shared<Thread>());
  std::shared_ptr<Thread> thread = queued_threads_.back();
  if (!thread) {
    UnlockQueuedThreads();
    return nullptr;
  }

  thread->state = Thread::ThreadState::QUEUED;
  thread->start_routine = function;
  thread->arg = arg;
  thread->lock = PTHREAD_MUTEX_INITIALIZER;
  UnlockQueuedThreads();
  return thread;
}

int ThreadManager::CreateThread(const std::function<void *(void *)> &function,
                                void *const arg, pthread_t *const thread_id) {
  // Add thread entry point to queue of waiting jobs.
  std::shared_ptr<Thread> thread = QueueThread(function, arg);
  if (!thread) {
    return -1;
  }
  int ret = pthread_mutex_lock(&thread->lock);
  if (ret != 0) {
    return ret;
  }

  // Exit and create a thread to enter with EnterAndDonateThread().
  if (enc_untrusted_create_thread(GetEnclaveName().c_str())) {
    return -1;
  }

  // Wait until a thread enters and executes the job.
  while (thread->state == Thread::ThreadState::QUEUED) {
    if (pthread_cond_wait(&thread->state_change_cond, &thread->lock)) {
      abort();
    }
  }

  if (thread_id) {
    *thread_id = thread->thread_id;
  }

  return pthread_mutex_unlock(&thread->lock);
}

int ThreadManager::StartThread() {
  LockQueuedThreads();
  // If there are no jobs waiting to be executed, abort.
  if (queued_threads_.empty()) {
    UnlockQueuedThreads();
    abort();
  }

  LockThreadsList();
  // Move Thread from queued_threads_ onto threads_.
  std::shared_ptr<Thread> thread = AllocateThread(queued_threads_.front());
  queued_threads_.pop();
  UnlockQueuedThreads();
  UnlockThreadsList();
  if (!thread) {
    return -1;
  }

  pthread_t self = pthread_self();
  int ret = thread->UpdateThreadState(self, Thread::ThreadState::RUNNING);
  if (ret != 0) {
    return ret;
  }

  // Run the job.
  thread->ret = thread->start_routine(thread->arg);

  ret = thread->UpdateThreadState(self, Thread::ThreadState::DONE);
  if (ret != 0) {
    return ret;
  }

  // Wait until the thread is joined.
  ret = pthread_mutex_lock(&thread->lock);
  if (ret != 0) {
    return ret;
  }
  while (thread->state != Thread::ThreadState::JOINED) {
    if (pthread_cond_wait(&thread->state_change_cond, &thread->lock)) {
      abort();
    }
  }

  return 0;
}

int ThreadManager::JoinThread(const pthread_t thread_id, void **return_value) {
  LockThreadsList();
  std::shared_ptr<Thread> thread = GetThread(thread_id);
  UnlockThreadsList();
  if (!thread) {
    return -1;
  }

  // Wait until the job is finished executing.
  int ret = pthread_mutex_lock(&thread->lock);
  if (ret != 0) {
    return ret;
  }
  while (thread->state != Thread::ThreadState::DONE) {
    if (pthread_cond_wait(&thread->state_change_cond, &thread->lock)) {
      abort();
    }
  }

  if (return_value) {
    *return_value = thread->ret;
  }

  ret = pthread_mutex_unlock(&thread->lock);
  if (ret != 0) {
    return ret;
  }

  ret = thread->UpdateThreadState(thread_id, Thread::ThreadState::JOINED);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

std::shared_ptr<ThreadManager::Thread> ThreadManager::AllocateThread(
    std::shared_ptr<Thread> thread) {
  pthread_t thread_id = pthread_self();
  threads_[thread_id] = thread;

  int ret = thread->UpdateThreadState(thread_id, Thread::ThreadState::RUNNING);
  if (ret != 0) {
    abort();
  }

  return thread;
}

std::shared_ptr<ThreadManager::Thread> ThreadManager::GetThread(
    pthread_t thread_id) {
  std::shared_ptr<Thread> ret = nullptr;
  if (threads_.find(thread_id) != threads_.end()) {
    ret = threads_[thread_id];
  }
  return ret;
}

void ThreadManager::LockThreadsList() {
  if (pthread_mutex_lock(&threads_lock_) != 0) {
    abort();
  }
}

void ThreadManager::UnlockThreadsList() {
  if (pthread_mutex_unlock(&threads_lock_) != 0) {
    abort();
  }
}

void ThreadManager::LockQueuedThreads() {
  if (pthread_mutex_lock(&scheduled_lock_) != 0) {
    abort();
  }
}

void ThreadManager::UnlockQueuedThreads() {
  if (pthread_mutex_unlock(&scheduled_lock_) != 0) {
    abort();
  }
}

}  // namespace asylo
