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

#include "absl/strings/str_cat.h"

namespace asylo {
namespace primitives {

PrimitiveStatus MakePrimitiveStatus(const Status& status) {
  if (status.error_space() != error::GoogleErrorSpace::GetInstance()) {
    std::string error_message = absl::StrCat(
        "Could not convert error space '", status.error_space()->SpaceName(),
        "' to an asylo PrimitiveStatus: Unexpected error space. Status dump: ",
        status.ToString());

    return PrimitiveStatus(error::GoogleError::OUT_OF_RANGE, error_message);
  }

  return PrimitiveStatus{status.error_code(), status.error_message().data(),
                         status.error_message().size()};
}

Status MakeStatus(const PrimitiveStatus& primitiveStatus) {
  return Status{error::GoogleErrorSpace::GetInstance(),
                primitiveStatus.error_code(), primitiveStatus.error_message()};
}

}  // namespace primitives
}  // namespace asylo
