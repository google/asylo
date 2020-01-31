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

#ifndef ASYLO_PLATFORM_POSIX_SIGNAL_SIGNAL_MANAGER_H_
#define ASYLO_PLATFORM_POSIX_SIGNAL_SIGNAL_MANAGER_H_

#include <signal.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>

#include "asylo/platform/core/trusted_spin_lock.h"
#include "asylo/util/status.h"

namespace asylo {

constexpr int kNumberSignals = NSIG;

// SignalManager class is a singleton responsible for maintaining mapping
// between signum and registered signal handlers.
class SignalManager {
 public:
  // The reset status of a signal handler. Whether it shouldn't be reset, should
  // be reset after a handling a signal, or has already been reset.
  enum class ResetStatus {
    NOT_AVAILABLE = 0,
    NO_RESET = 1,
    TO_BE_RESET = 2,
    RESET = 3,
  };

  static SignalManager *GetInstance();

  // Locates and calls the handler registered for |signum|.
  void HandleSignal(int signum, siginfo_t *info, void *ucontext);

  // Sets a signal handler pointer for a specific signal |signum|.
  void SetSigAction(int signum, const struct sigaction &act);

  // Gets a signal handler for a specific signal |signum|.
  bool GetSigAction(int signum, struct sigaction *act);

  // Remove a signal handler for a specific signal |signum|.
  void ClearSigAction(int signum);

  // Blocks all the signals in |set|.
  void BlockSignals(const sigset_t &set);

  // Unblocks all the signals in |set|.
  void UnblockSignals(const sigset_t &set);

  // Gets the enclave stored signal mask.
  sigset_t GetSignalMask() const;

  // Sets the enclave stored signal mask to |mask|.
  void SetSignalMask(const sigset_t &mask);

  // Gets the set of unblocked signals in |set|.
  sigset_t GetUnblockedSet(const sigset_t &set);

  // Sets the reset status of a signal to |status|.
  void SetResetStatus(int signum, ResetStatus status);

  // Gets the reset status of a signal.
  ResetStatus GetResetStatus(int signum);

 private:
  SignalManager();  // Private to enforce singleton.
  SignalManager(SignalManager const &) = delete;
  void operator=(SignalManager const &) = delete;

  // Use spin lock in SignalManager to avoid exiting the enclave while handling
  // the signal.
  TrustedSpinLock signal_maps_lock_;

  std::unordered_map<int, std::unique_ptr<struct sigaction>>
      signal_to_sigaction_;

  std::array<ResetStatus, kNumberSignals> signal_to_reset_;

  thread_local static sigset_t signal_mask_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_SIGNAL_SIGNAL_MANAGER_H_
