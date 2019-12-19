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

#ifndef ASYLO_PLATFORM_PRIMITIVES_UTIL_EXIT_LOG_H_
#define ASYLO_PLATFORM_PRIMITIVES_UTIL_EXIT_LOG_H_

#include <functional>
#include <ostream>
#include <vector>

#include "absl/time/clock.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/util/status.h"

namespace asylo {
namespace primitives {

// A log entry representing a single exit call.
class ExitLogEntry {
 public:
  ExitLogEntry(absl::Time start, absl::Duration duration,
               uint64_t untrusted_selector);
  friend std::ostream& operator<<(std::ostream& os, const ExitLogEntry& entry);

 private:
  const absl::Time start_;
  const absl::Duration duration_;
  const uint64_t untrusted_selector_;
};

// A hook which will log a single exit call.
class ExitLogHook : public DispatchTable::ExitHook {
 public:
  explicit ExitLogHook(std::function<void(ExitLogEntry)> store_log_entry);
  Status PreExit(uint64_t untrusted_selector) override;
  Status PostExit(Status result) override;

 private:
  absl::Time start_;
  uint64_t untrusted_selector_;
  const std::function<void(ExitLogEntry)> store_log_entry_;
};

// A hook factory which will generate one hook object per exit call.
class ExitLogHookFactory : public DispatchTable::ExitHookFactory {
 public:
  ExitLogHookFactory() = default;
  std::unique_ptr<DispatchTable::ExitHook> CreateExitHook() override;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_UTIL_EXIT_LOG_H_
