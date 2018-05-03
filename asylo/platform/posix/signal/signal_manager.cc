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

namespace asylo {

SignalManager *SignalManager::GetInstance() {
  static SignalManager *instance = new SignalManager();
  return instance;
}

void SignalManager::SetSignalHandler(int signum, sighandler_t handler) {
  absl::MutexLock lock(&signal_to_handler_lock_);
  signal_to_handler_[signum] = handler;
}

const sighandler_t SignalManager::GetSignalHandler(int signum) {
  absl::MutexLock lock(&signal_to_handler_lock_);
  if (signal_to_handler_.find(signum) == signal_to_handler_.end()) {
    return nullptr;
  }
  return signal_to_handler_[signum];
}

}  // namespace asylo
