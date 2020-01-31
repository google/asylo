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

#include "asylo/platform/posix/signal/signal_manager.h"

#include <signal.h>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "asylo/util/lock_guard.h"

namespace asylo {
namespace {

constexpr int kMaxSignalsInMask = sizeof(sigset_t) * 8;

sigset_t EmptySigSet() {
  sigset_t set;
  sigemptyset(&set);
  return set;
}

}  // namespace

thread_local sigset_t SignalManager::signal_mask_ = EmptySigSet();

// Initialize the spin locks to be recursive so that signal handling does not
// cause deadlock if a signal arrives while the thread is registering a signal.
SignalManager::SignalManager() : signal_maps_lock_(/*is_recursive=*/true) {
  signal_to_reset_.fill(ResetStatus::NO_RESET);
}

SignalManager *SignalManager::GetInstance() {
  static SignalManager *instance = new SignalManager();
  return instance;
}

void SignalManager::HandleSignal(int signum, siginfo_t *info, void *ucontext) {
  struct sigaction act;
  // Return if the signal handler is already reset to default.
  if (GetResetStatus(signum) == ResetStatus::RESET ||
      !GetSigAction(signum, &act)) {
    return;
  }
  // If it's the first time a to-be-reset signal arrives, continue invoking the
  // handler, but mark the signal as reset.
  if (GetResetStatus(signum) == ResetStatus::TO_BE_RESET) {
    SetResetStatus(signum, ResetStatus::RESET);
  }
  sigset_t old_mask = GetSignalMask();
  BlockSignals(act.sa_mask);
  bool is_siginfo = act.sa_flags & SA_SIGINFO;
  if (is_siginfo && act.sa_sigaction) {
    act.sa_sigaction(signum, info, ucontext);
  } else if (!is_siginfo && act.sa_handler) {
    act.sa_handler(signum);
  }
  SetSignalMask(old_mask);
}

void SignalManager::SetSigAction(int signum, const struct sigaction &act) {
  // To avoid deadlock, block all signals before registering a signal handler.
  sigset_t mask;
  sigfillset(&mask);
  sigset_t old_mask;
  sigprocmask(SIG_SETMASK, &mask, &old_mask);
  {
    LockGuard lock(&signal_maps_lock_);
    signal_to_sigaction_[signum] = absl::make_unique<struct sigaction>(act);
  }
  // Set the signal mask back to the original one to unblock the signals.
  sigprocmask(SIG_SETMASK, &old_mask, nullptr);
}

bool SignalManager::GetSigAction(int signum, struct sigaction *act) {
  LockGuard lock(&signal_maps_lock_);
  auto sigaction_iterator = signal_to_sigaction_.find(signum);
  if (sigaction_iterator == signal_to_sigaction_.end()) {
    return false;
  }
  *act = *sigaction_iterator->second;
  return true;
}

void SignalManager::ClearSigAction(int signum) {
  LockGuard lock(&signal_maps_lock_);
  signal_to_sigaction_.erase(signum);
}

void SignalManager::BlockSignals(const sigset_t &set) {
  for (int signum = 0; signum < kMaxSignalsInMask; ++signum) {
    if (sigismember(&set, signum)) {
      sigaddset(&signal_mask_, signum);
    }
  }
}

void SignalManager::UnblockSignals(const sigset_t &set) {
  for (int signum = 0; signum < kMaxSignalsInMask; ++signum) {
    if (sigismember(&set, signum)) {
      sigdelset(&signal_mask_, signum);
    }
  }
}

sigset_t SignalManager::GetSignalMask() const { return signal_mask_; }

void SignalManager::SetSignalMask(const sigset_t &mask) { signal_mask_ = mask; }

sigset_t SignalManager::GetUnblockedSet(const sigset_t &set) {
  sigset_t signals_to_unblock;
  sigemptyset(&signals_to_unblock);
  for (int signum = 0; signum < kMaxSignalsInMask; ++signum) {
    if (!sigismember(&set, signum)) {
      sigaddset(&signals_to_unblock, signum);
    }
  }
  return signals_to_unblock;
}

void SignalManager::SetResetStatus(int signum,
                                   SignalManager::ResetStatus status) {
  if (signum < 0 || signum >= kNumberSignals) {
    return;
  }
  LockGuard lock(&signal_maps_lock_);
  signal_to_reset_[signum] = status;
}

SignalManager::ResetStatus SignalManager::GetResetStatus(int signum) {
  if (signum < 0 || signum >= kNumberSignals) {
    return ResetStatus::NOT_AVAILABLE;
  }
  LockGuard lock(&signal_maps_lock_);
  return signal_to_reset_[signum];
}

}  // namespace asylo
