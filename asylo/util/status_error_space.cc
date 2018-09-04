/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/util/status_error_space.h"

namespace asylo {
namespace error {

ErrorSpace const *StatusErrorSpace::GetInstance() {
  static ErrorSpace const *instance = new StatusErrorSpace();
  return instance;
}

StatusErrorSpace::StatusErrorSpace()
    : ErrorSpaceImplementationHelper<StatusErrorSpace>(
          "::asylo::error::StatusErrorSpace") {
  AddTranslationMapEntry(static_cast<int>(StatusError::MOVED), "MOVED",
                         GoogleError::INTERNAL);
  AddTranslationMapEntry(static_cast<int>(StatusError::RESTORE_ERROR),
                         "RESTORE_ERROR", GoogleError::INTERNAL);
}

ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<StatusError> tag) {
  return StatusErrorSpace::GetInstance();
}

}  // namespace error
}  // namespace asylo
