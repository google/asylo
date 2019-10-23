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

#ifndef ASYLO_EXAMPLES_REMOTE_BOUNCING_CIRCLES_CIRCLE_CLIENT_H_
#define ASYLO_EXAMPLES_REMOTE_BOUNCING_CIRCLES_CIRCLE_CLIENT_H_

#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include "absl/strings/string_view.h"

namespace asylo {

class CircleStatus {
 public:
  CircleStatus() = default;
  virtual ~CircleStatus() = default;

  virtual std::tuple<int32_t, int32_t, int32_t, std::string> Update() = 0;

  static void InitializeGlobal(size_t n, absl::string_view enclave_prefix,
                               int32_t width, int32_t height);
  static std::vector<std::unique_ptr<CircleStatus>> *circles();
};

}  // namespace asylo

#endif  // ASYLO_EXAMPLES_REMOTE_BOUNCING_CIRCLES_CIRCLE_CLIENT_H_
