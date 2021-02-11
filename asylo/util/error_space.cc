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

#include "asylo/util/error_space.h"

#include "absl/status/status.h"

namespace asylo {
namespace error {

ErrorSpace const *ErrorSpace::Find(const std::string &name) {
  auto iter = error_internal::AsyloErrorSpaceStaticMap::GetValue(name);
  return (iter == error_internal::AsyloErrorSpaceStaticMap::value_end())
             ? nullptr
             : &*iter;
}

ErrorSpace const *GetErrorSpace(
    ErrorSpaceAdlTag<::asylo::error::GoogleError> tag) {
  return GoogleErrorSpace::GetInstance();
}

ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<::absl::StatusCode> tag) {
  return GoogleErrorSpace::GetInstance();
}

GoogleErrorSpace::GoogleErrorSpace()
    : ErrorSpaceImplementationHelper<GoogleErrorSpace>(
          kCanonicalErrorSpaceName) {
  AddTranslationMapEntry(OK, "OK", OK);
  AddTranslationMapEntry(CANCELLED, "CANCELLED", CANCELLED);
  AddTranslationMapEntry(UNKNOWN, "UNKNOWN", UNKNOWN);
  AddTranslationMapEntry(INVALID_ARGUMENT, "INVALID_ARGUMENT",
                         INVALID_ARGUMENT);
  AddTranslationMapEntry(DEADLINE_EXCEEDED, "DEADLINE_EXCEEDED",
                         DEADLINE_EXCEEDED);
  AddTranslationMapEntry(NOT_FOUND, "NOT_FOUND", NOT_FOUND);
  AddTranslationMapEntry(ALREADY_EXISTS, "ALREADY_EXISTS", ALREADY_EXISTS);
  AddTranslationMapEntry(PERMISSION_DENIED, "PERMISSION_DENIED",
                         PERMISSION_DENIED);
  AddTranslationMapEntry(RESOURCE_EXHAUSTED, "RESOURCE_EXHAUSTED",
                         RESOURCE_EXHAUSTED);
  AddTranslationMapEntry(FAILED_PRECONDITION, "FAILED_PRECONDITION",
                         FAILED_PRECONDITION);
  AddTranslationMapEntry(ABORTED, "ABORTED", ABORTED);
  AddTranslationMapEntry(OUT_OF_RANGE, "OUT_OF_RANGE", OUT_OF_RANGE);
  AddTranslationMapEntry(UNIMPLEMENTED, "UNIMPLEMENTED", UNIMPLEMENTED);
  AddTranslationMapEntry(INTERNAL, "INTERNAL", INTERNAL);
  AddTranslationMapEntry(UNAVAILABLE, "UNAVAILABLE", UNAVAILABLE);
  AddTranslationMapEntry(DATA_LOSS, "DATA_LOSS", DATA_LOSS);
  AddTranslationMapEntry(UNAUTHENTICATED, "UNAUTHENTICATED", UNAUTHENTICATED);
}

}  // namespace error
}  // namespace asylo
