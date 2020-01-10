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

// A variation of DispatchTable that performs logging of exit calls, if
// `enable_logging` parameter in constructor is true (otherwise it is identical
// to the regular DispatchTable).
class LoggingDispatchTable : public DispatchTable {
 public:
  explicit LoggingDispatchTable(bool enable_logging);
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_UTIL_EXIT_LOG_H_
