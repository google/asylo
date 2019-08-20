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

#include "asylo/platform/primitives/sgx/exit_handlers.h"

namespace asylo {
namespace primitives {

Status CreateThreadHandler(const std::shared_ptr<primitives::Client> &client,
                           void *context, primitives::MessageReader *input,
                           primitives::MessageWriter *output) {
  return Status::OkStatus();
}

}  // namespace primitives
}  // namespace asylo