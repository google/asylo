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

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "asylo/util/status.h"

namespace asylo {

// SignalManager class is a singleton responsible for maintaining mapping
// between signum and registered signal handlers.
class SignalManager {
 public:
  static SignalManager *GetInstance();

  // Locates and calls the handler registered for |signum|.
  Status HandleSignal(int signum, siginfo_t *info, void *ucontext);

  // Sets a signal handler pointer for a specific signal |signum|.
  void SetSigAction(int signum, const struct sigaction &act)
      LOCKS_EXCLUDED(signal_to_sigaction_lock_);

  // Gets a signal handler for a specific signal |signum|.
  const struct sigaction *GetSigAction(int signum) const
      LOCKS_EXCLUDED(signal_to_sigaction_lock_);

  // Blocks all the signals in |set|.
  void BlockSignals(const sigset_t &set);

  // Unblocks all the signals in |set|.
  void UnblockSignals(const sigset_t &set);

  // Gets the enclave stored signal mask.
  const sigset_t GetSignalMask() const;

  // Sets the enclave stored signal mask to |mask|.
  void SetSignalMask(const sigset_t &mask);

  // Gets the set of unblocked signals in |set|.
  const sigset_t GetUnblockedSet(const sigset_t &set);

 private:
  SignalManager() = default;  // Private to enforce singleton.
  SignalManager(SignalManager const &) = delete;
  void operator=(SignalManager const &) = delete;

  mutable absl::Mutex signal_to_sigaction_lock_;
  absl::flat_hash_map<int, std::unique_ptr<struct sigaction>>
      signal_to_sigaction_ GUARDED_BY(signal_to_sigaction_lock_);

  thread_local static sigset_t signal_mask_;
};

}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_SIGNAL_SIGNAL_MANAGER_H_
