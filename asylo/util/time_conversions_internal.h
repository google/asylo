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

#ifndef ASYLO_UTIL_TIME_CONVERSIONS_INTERNAL_H_
#define ASYLO_UTIL_TIME_CONVERSIONS_INTERNAL_H_

#include "google/protobuf/duration.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include "absl/time/time.h"
#include "asylo/util/status.h"
#include "include/grpc/impl/codegen/gpr_types.h"

namespace asylo {
namespace internal {

// In each of the following conversion functions, if |source| cannot be
// precisely represented in the output type but lies between two finite values
// that the output type can represent, then |dest| is set to one of those two
// values. If |source| is finite but greater than the maximum or less than the
// minimum finite value representable by the output type, then an OUT_OF_RANGE
// error is returned.
//
// The conversion functions only set |dest| to an infinite value if |source|
// represents an infinite value and the output type supports infinite values.

// Converts a representation of a duration of time to an absl::Duration. Each
// overload for a type DurationT (which may be a const-reference) must have the
// signature:
//
//     Status ToAbslDuration(DurationT source, absl::Duration *dest);
//
// Also see the constraints above.
Status ToAbslDuration(absl::Duration source, absl::Duration *dest);
Status ToAbslDuration(const google::protobuf::Duration &source,
                      absl::Duration *dest);
Status ToAbslDuration(gpr_timespec source, absl::Duration *dest);

// Converts an absl::Duration to another representation of a duration of time.
// Each overload for a type DurationT must have the signature:
//
//     Status FromAbslDuration(absl::Duration source, DurationT *dest);
//
// Also see the constraints above.
Status FromAbslDuration(absl::Duration source, absl::Duration *dest);
Status FromAbslDuration(absl::Duration source,
                        google::protobuf::Duration *dest);
Status FromAbslDuration(absl::Duration source, gpr_timespec *dest);

// Converts a representation of a point in time to an absl::Time. Each overload
// for a type TimeT (which may be a const-reference) must have the signature:
//
//     Status ToAbslTime(TimeT source, absl::Time *dest);
//
// Also see the constraints above.
Status ToAbslTime(absl::Time source, absl::Time *dest);
Status ToAbslTime(const google::protobuf::Timestamp &source, absl::Time *dest);
Status ToAbslTime(gpr_timespec source, absl::Time *dest);

// Converts an absl::Time to another representation of a point in time. Each
// overload for a type TimeT must have the signature:
//
//     Status FromAbslTime(absl::Time source, TimeT *dest);
//
// Also see the constraints above.
Status FromAbslTime(absl::Time source, absl::Time *dest);
Status FromAbslTime(absl::Time source, google::protobuf::Timestamp *dest);
Status FromAbslTime(absl::Time source, gpr_timespec *dest);

}  // namespace internal
}  // namespace asylo

#endif  // ASYLO_UTIL_TIME_CONVERSIONS_INTERNAL_H_
