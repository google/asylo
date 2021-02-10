/*
 * Copyright 2021 Asylo authors
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
 */

#ifndef ASYLO_UTIL_STATUS_HELPERS_INTERNAL_H_
#define ASYLO_UTIL_STATUS_HELPERS_INTERNAL_H_

#include "absl/status/status.h"
#include "asylo/util/status.h"

namespace asylo {
namespace internal {

// An implementation struct for ConvertStatus(). Each specialization must have a
// method with the signature:
//
//     static ToStatusT Convert(const FromStatusT &from_status);
template <typename ToStatusT, typename FromStatusT>
struct ConvertStatusImpl;

// A specialization for converting to asylo::Status.
template <typename FromStatusT>
struct ConvertStatusImpl<Status, FromStatusT> {
  static Status Convert(const FromStatusT &from_status) {
    return Status(from_status);
  }
};

// A specialization for converting to absl::Status.
template <typename FromStatusT>
struct ConvertStatusImpl<absl::Status, FromStatusT> {
  static absl::Status Convert(const FromStatusT &from_status) {
    // Use operator absl::Status().
    return Status(from_status);
  }
};

// Most generic specialization.
template <typename ToStatusT, typename FromStatusT>
struct ConvertStatusImpl {
  static ToStatusT Convert(const FromStatusT &from_status) {
    return Status(from_status).ToOtherStatus<ToStatusT>();
  }
};

}  // namespace internal
}  // namespace asylo

#endif  // ASYLO_UTIL_STATUS_HELPERS_INTERNAL_H_
