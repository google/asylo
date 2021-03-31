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

#include "asylo/platform/primitives/util/status_conversions.h"

#include "absl/status/status.h"
#include "asylo/platform/primitives/primitive_status.h"

namespace asylo {
namespace primitives {

PrimitiveStatus MakePrimitiveStatus(const Status& status) {
  return PrimitiveStatus{static_cast<int>(status.code()),
                         status.message().data(), status.message().size()};
}

Status MakeStatus(const PrimitiveStatus& primitive_status) {
  return Status{static_cast<absl::StatusCode>(primitive_status.error_code()),
                primitive_status.error_message()};
}

}  // namespace primitives
}  // namespace asylo
