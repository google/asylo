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

#ifndef ASYLO_UTIL_STATUS_ERROR_SPACE_H_
#define ASYLO_UTIL_STATUS_ERROR_SPACE_H_

#include "absl/base/attributes.h"
#include "asylo/util/error_space.h"

namespace asylo {
namespace error {

// Error codes used by Status and StatusOr objects to represent internal errors
// and invalid operations. This error space is provided strictly for internal
// use in Status and StatusOr only. It should not be used outside of the Status
// and StatusOr classes.
enum class ABSL_DEPRECATED(
    "Deprecated as part of Asylo's absl::Status migration. Do not depend on "
    "the state of a moved-from Status or StatusOr<T> object, and do not try to "
    "programatically distinguish a Status resulting from a failed "
    "deserialization from a successfully deserialized error Status.")
    StatusError : int {
      OK = 0,

      // Indicates that the Status object was moved and is no longer valid.
      MOVED = 1,

      // Indicates that the source StatusProto from which this Status was
      // restored was invalid.
      RESTORE_ERROR = 2,
    };

// Implementation of the ErrorSpace interface for the StatusError enum.
class ABSL_DEPRECATED(
    "Deprecated as part of Asylo's absl::Status migration. Do not depend on "
    "the state of a moved-from Status or StatusOr<T> object, and do not try to "
    "programatically distinguish a Status resulting from a failed "
    "deserialization from a successfully deserialized error Status.")
    StatusErrorSpace : public ErrorSpaceImplementationHelper<StatusErrorSpace> {
 public:
  using code_type = StatusError;

  StatusErrorSpace(const StatusErrorSpace &) = delete;
  StatusErrorSpace &operator=(const StatusErrorSpace &) = delete;

  // Returns a singleton instance of StatusErrorSpace.
  static ErrorSpace const *GetInstance();

 private:
  StatusErrorSpace();
};

// Returns a singleton instance of the ErrorSpace implementation corresponding
// to the StatusError enum.
ABSL_DEPRECATED(
    "Deprecated as part of Asylo's absl::Status migration. Do not depend on "
    "the state of a moved-from Status or StatusOr<T> object, and do not try to "
    "programatically distinguish a Status resulting from a failed "
    "deserialization from a successfully deserialized error Status.")
ErrorSpace const *GetErrorSpace(ErrorSpaceAdlTag<StatusError> tag);

}  // namespace error
}  // namespace asylo

#endif  // ASYLO_UTIL_STATUS_ERROR_SPACE_H_
