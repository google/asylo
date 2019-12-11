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

#ifndef ASYLO_UTIL_TIME_CONVERSIONS_H_
#define ASYLO_UTIL_TIME_CONVERSIONS_H_

#include "absl/time/time.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "asylo/util/time_conversions_internal.h"

namespace asylo {

// Converts between representations of a duration of time. The following types
// are supported:
//
//   * absl::Duration
//   * google::protobuf::Duration
//   * gpr_timespec, but only with a |clock_type| of GPR_TIMESPAN
//
// If |from| cannot be precisely represented in DestT but lies between two
// finite durations that DestT can represent, then one of those two durations is
// returned. If |from| is finite but greater than the maximum or less than the
// minimum finite duration representable by DestT, then an OUT_OF_RANGE error is
// returned.
//
// ConvertDuration() only returns an infinite duration if |from| represents an
// infinite duration and DestT supports infinite durations.
//
// ConvertDuration() uses absl::Duration as an intermediate type, so values
// outside the range of absl::Duration cannot be converted, even if those values
// are in the ranges of both SourceT and DestT.
template <typename DestT, typename SourceT>
StatusOr<DestT> ConvertDuration(SourceT from) {
  absl::Duration intermediate;
  ASYLO_RETURN_IF_ERROR(internal::ToAbslDuration(from, &intermediate));
  DestT result;
  ASYLO_RETURN_IF_ERROR(internal::FromAbslDuration(intermediate, &result));
  return result;
}

// Converts between representations of a point in time. The following types are
// supported:
//
//   * absl::Time
//   * google::protobuf::Timestamp
//   * gpr_timespec, but only with a |clock_type| of GPR_CLOCK_REALTIME
//
// If |from| cannot be precisely represented in DestT but lies between two
// finite time points that DestT can represent, then one of those two time
// points is returned. If |from| is finite but greater than the maximum or less
// than the minimum finite time point representable by DestT, then an
// OUT_OF_RANGE error is returned.
//
// ConvertTime() only returns an infinite time point if |from| represents an
// infinite time point and DestT supports infinite time points.
//
// ConvertTime() uses absl::Time as an intermediate type, so values outside the
// range of absl::Time cannot be converted, even if those values are in the
// ranges of both SourceT and DestT.
template <typename DestT, typename SourceT>
StatusOr<DestT> ConvertTime(SourceT from) {
  absl::Time intermediate;
  ASYLO_RETURN_IF_ERROR(internal::ToAbslTime(from, &intermediate));
  DestT result;
  ASYLO_RETURN_IF_ERROR(internal::FromAbslTime(intermediate, &result));
  return result;
}

}  // namespace asylo

#endif  // ASYLO_UTIL_TIME_CONVERSIONS_H_
