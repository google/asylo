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

#ifndef ASYLO_UTIL_REMOTE_PROCESS_MAIN_WRAPPER_H_
#define ASYLO_UTIL_REMOTE_PROCESS_MAIN_WRAPPER_H_

#include <signal.h>
#include <string.h>

#include <memory>
#include <utility>

#include "absl/status/status.h"
#include "asylo/util/logging.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/thread.h"

namespace asylo {

// Wrapper template adds SIGTERM capture and graceful handling
// to a generic activity class, which must export Create factory method and
// Signal and Wait methods.
// Usage pattern:
//
// class ActivityImpl {
//  public:
//   static ::asylo::util::StatusOr<std::unique_ptr<ActivityImpl>>
//   Create(arguments) {
//     auto activity = absl::WrapUnique(new ActivityImpl(arguments));
//     ...
//     return activity;
//   }
//   void Kill(int signum) { ... }  // Let the Activity process the signal.
//   void Wait() { ... }  // Wait until Activity actually shuts down.
//  private:
//   ActivityImpl(arguments) { ... }
//   ...
// };
// int main(int argc, char *argv[]) {
//   absl::ParseCommandLine(argc, argv);
//   ::asylo::primitives::ProcessMainWrapper<ActivityImpl>::RunUntilTerminated(
//       arguments to be passed to Create);
// }
template <typename T>
class ProcessMainWrapper {
 public:
  explicit ProcessMainWrapper(std::unique_ptr<T> wrapped_instance)
      : wrapped_instance_(CHECK_NOTNULL(std::move(wrapped_instance))) {
    // Set up SIGTERM action.
    term_action_ = new struct sigaction();
    memset(term_action_, 0, sizeof(struct sigaction));
    term_action_->sa_handler = &ProcessMainWrapper::TermHandler;
    sigaction(SIGTERM, term_action_, nullptr);
  }

  ~ProcessMainWrapper() {
    delete term_action_;
    term_action_ = nullptr;
    wrapper_ = nullptr;
  }

  // Process activity.
  template <typename... Args>
  static Status RunUntilTerminated(Args &&... args) {
    // Instantiate activity to run.
    std::unique_ptr<T> activity;
    ASYLO_ASSIGN_OR_RETURN(activity, T::Create(std::forward<Args>(args)...));

    // Create the fixture.
    auto wrapper = absl::make_unique<ProcessMainWrapper>(std::move(activity));
    wrapper_ = wrapper.get();

    // Wait for the wrapped_instance to disconnect (after SIGTERM signal)
    // on a separate thread (to exclude any Mutex impact).
    Thread wait_thread([&wrapper] { wrapper->wrapped_instance_->Wait(); });
    wait_thread.Join();
    return absl::OkStatus();
  }

 private:
  static void TermHandler(int signum) {
    // On SIGTERM stop wrapped_instance.
    if (wrapper_) {
      wrapper_->wrapped_instance_->Kill(signum);
    }
  }

  static ProcessMainWrapper *wrapper_;
  static struct sigaction *term_action_;
  const std::unique_ptr<T> wrapped_instance_;
};

template <typename T>
ProcessMainWrapper<T> *ProcessMainWrapper<T>::wrapper_;

template <typename T>
struct sigaction *ProcessMainWrapper<T>::term_action_ = nullptr;

}  // namespace asylo

#endif  // ASYLO_UTIL_REMOTE_PROCESS_MAIN_WRAPPER_H_
