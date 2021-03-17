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

#include "asylo/util/time_conversions_internal.h"

#include <cmath>
#include <cstdint>
#include <string>

#include "google/protobuf/duration.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include <google/protobuf/message.h>
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/time_util.h>
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "asylo/util/status.h"
#include "include/grpc/impl/codegen/gpr_types.h"
#include "include/grpc/support/time.h"

namespace asylo {
namespace internal {
namespace {

// Represents a given number of seconds and nanoseconds.
struct SecondsNanos {
  int64_t seconds;

  // Must have same sign as |seconds|, or any sign if |seconds| is 0.
  int32_t nanos;
};

// Returns the text-format representation of |message| or a placeholder value if
// |message| cannot be printed to the text format.
std::string MessageToString(const google::protobuf::Message &message) {
  std::string printed;
  if (!google::protobuf::TextFormat::PrintToString(message, &printed)) {
    printed = "<unprintable>";
  }
  return printed;
}

// Returns a string representation of |time|.
std::string GprTimespecToString(gpr_timespec time) {
  absl::string_view clock_type_name;
  switch (time.clock_type) {
    case GPR_CLOCK_MONOTONIC:
      clock_type_name = "GPR_CLOCK_MONOTONIC";
      break;
    case GPR_CLOCK_REALTIME:
      clock_type_name = "GPR_CLOCK_REALTIME";
      break;
    case GPR_CLOCK_PRECISE:
      clock_type_name = "GPR_CLOCK_PRECISE";
      break;
    case GPR_TIMESPAN:
      clock_type_name = "GPR_TIMESPAN";
      break;
    default:
      clock_type_name = "<unknown clock type>";
      break;
  }

  if (gpr_time_cmp(time, gpr_inf_past(time.clock_type)) == 0) {
    return absl::StrFormat("-infinity on %s", clock_type_name);
  }
  if (gpr_time_cmp(time, gpr_inf_future(time.clock_type)) == 0) {
    return absl::StrFormat("+infinity on %s", clock_type_name);
  }
  return absl::StrFormat("{tv_sec = %d, tv_nsec = %d, clock_type = %s}",
                         time.tv_sec, time.tv_nsec, clock_type_name);
}

// Returns an INVALID_ARGUMENT error indicating that |type_value| is an invalid
// instance of type |type_name|.
Status InvalidInstanceError(absl::string_view type_name,
                            absl::string_view type_value) {
  return absl::InvalidArgumentError(
      absl::StrFormat("Invalid %s value: %s", type_name, type_value));
}

// Returns an OUT_OF_RANGE error indicating that the value |source_type_value|
// of type |source_type_name| cannot be represented by type |dest_type_name|.
Status CannotRepresentError(absl::string_view source_type_name,
                            absl::string_view dest_type_name,
                            absl::string_view source_type_value) {
  return absl::OutOfRangeError(
      absl::StrFormat("Cannot represent %s value \"%s\" as %s",
                      source_type_name, source_type_value, dest_type_name));
}

// Returns true if |duration| is finite and false otherwise.
bool IsFiniteDuration(absl::Duration duration) {
  return duration != -absl::InfiniteDuration() &&
         duration != absl::InfiniteDuration();
}

// Returns true if |time| is finite and false otherwise.
bool IsFiniteTime(absl::Time time) {
  return time != absl::InfinitePast() && time != absl::InfiniteFuture();
}

// Converts |duration| to an amount of seconds and nanoseconds.
absl::optional<SecondsNanos> ToSecondsNanos(absl::Duration duration) {
  SecondsNanos result;
  absl::Duration nanos_duration;
  result.seconds =
      absl::IDivDuration(duration, absl::Seconds(1), &nanos_duration);
  if (nanos_duration <= absl::Seconds(-1) ||
      nanos_duration >= absl::Seconds(1)) {
    return absl::nullopt;
  }
  result.nanos = absl::ToInt64Nanoseconds(nanos_duration);
  return result;
}

// Returns true if a google::protobuf::Duration with |seconds| seconds and
// |nanos| nanoseconds would be a valid instance of the message.
bool IsValidDurationProto(int64_t seconds, int32_t nanos) {
  return seconds >= google::protobuf::util::TimeUtil::kDurationMinSeconds &&
         seconds <= google::protobuf::util::TimeUtil::kDurationMaxSeconds &&
         nanos >= -999999999 && nanos <= 999999999 &&
         (seconds == 0 || nanos == 0 ||
          std::signbit(seconds) == std::signbit(nanos));
}

// Returns true if a google::protobuf::Timestamp with |seconds| seconds and
// |nanos| nanoseconds would be a valid instance of the message.
bool IsValidTimestampProto(int64_t seconds, int32_t nanos) {
  return seconds >= google::protobuf::util::TimeUtil::kTimestampMinSeconds &&
         seconds <= google::protobuf::util::TimeUtil::kTimestampMaxSeconds &&
         nanos >= 0 && nanos <= 999999999;
}

}  // namespace

Status ToAbslDuration(absl::Duration source, absl::Duration *dest) {
  *dest = source;
  return absl::OkStatus();
}

Status ToAbslDuration(const google::protobuf::Duration &source,
                      absl::Duration *dest) {
  if (!IsValidDurationProto(source.seconds(), source.nanos())) {
    return InvalidInstanceError("google::protobuf::Duration",
                                MessageToString(source));
  }

  absl::Duration duration =
      absl::Seconds(source.seconds()) + absl::Nanoseconds(source.nanos());
  if (!IsFiniteDuration(duration)) {
    return CannotRepresentError("google::protobuf::Duration", "absl::Duration",
                                MessageToString(source));
  }
  *dest = duration;
  return absl::OkStatus();
}

Status ToAbslDuration(gpr_timespec source, absl::Duration *dest) {
  if (source.clock_type != GPR_TIMESPAN) {
    return InvalidInstanceError("gpr_timespec (as duration)",
                                GprTimespecToString(source));
  }
  if (gpr_time_cmp(source, gpr_inf_past(GPR_TIMESPAN)) == 0) {
    *dest = -absl::InfiniteDuration();
  } else if (gpr_time_cmp(source, gpr_inf_future(GPR_TIMESPAN)) == 0) {
    *dest = absl::InfiniteDuration();
  } else {
    *dest = absl::Seconds(source.tv_sec) + absl::Nanoseconds(source.tv_nsec);
  }
  return absl::OkStatus();
}

Status FromAbslDuration(absl::Duration source, absl::Duration *dest) {
  *dest = source;
  return absl::OkStatus();
}

Status FromAbslDuration(absl::Duration source,
                        google::protobuf::Duration *dest) {
  auto maybe_seconds_nanos = ToSecondsNanos(source);
  if (!maybe_seconds_nanos.has_value() ||
      !IsValidDurationProto(maybe_seconds_nanos.value().seconds,
                            maybe_seconds_nanos.value().nanos)) {
    return CannotRepresentError("absl::Duration", "google::protobuf::Duration",
                                absl::FormatDuration(source));
  }
  dest->set_seconds(maybe_seconds_nanos.value().seconds);
  dest->set_nanos(maybe_seconds_nanos.value().nanos);
  return absl::OkStatus();
}

Status FromAbslDuration(absl::Duration source, gpr_timespec *dest) {
  if (source == -absl::InfiniteDuration()) {
    *dest = gpr_inf_past(GPR_TIMESPAN);
    return absl::OkStatus();
  }
  if (source == absl::InfiniteDuration()) {
    *dest = gpr_inf_future(GPR_TIMESPAN);
    return absl::OkStatus();
  }
  auto maybe_seconds_nanos = ToSecondsNanos(source);
  if (!maybe_seconds_nanos.has_value()) {
    return CannotRepresentError("absl::Duration", "gpr_timespec",
                                absl::FormatDuration(source));
  }
  gpr_timespec time = gpr_time_add(
      gpr_time_from_seconds(maybe_seconds_nanos.value().seconds, GPR_TIMESPAN),
      gpr_time_from_nanos(maybe_seconds_nanos.value().nanos, GPR_TIMESPAN));
  if (gpr_time_cmp(time, gpr_inf_past(GPR_TIMESPAN)) == 0 ||
      gpr_time_cmp(time, gpr_inf_future(GPR_TIMESPAN)) == 0) {
    return CannotRepresentError("absl::Duration", "gpr_timespec",
                                absl::FormatDuration(source));
  }
  *dest = time;
  return absl::OkStatus();
}

Status ToAbslTime(absl::Time source, absl::Time *dest) {
  *dest = source;
  return absl::OkStatus();
}

Status ToAbslTime(const google::protobuf::Timestamp &source, absl::Time *dest) {
  if (!IsValidTimestampProto(source.seconds(), source.nanos())) {
    return InvalidInstanceError("google::protobuf::Timestamp",
                                MessageToString(source));
  }
  absl::Time time = absl::UnixEpoch() + absl::Seconds(source.seconds()) +
                    absl::Nanoseconds(source.nanos());
  if (!IsFiniteTime(time)) {
    return CannotRepresentError("google::protobuf::Timestamp", "absl::Time",
                                MessageToString(source));
  }
  *dest = time;
  return absl::OkStatus();
}

Status ToAbslTime(gpr_timespec source, absl::Time *dest) {
  if (source.clock_type != GPR_CLOCK_REALTIME) {
    return InvalidInstanceError("gpr_timespec (as time-point)",
                                GprTimespecToString(source));
  }

  if (gpr_time_cmp(source, gpr_inf_past(GPR_CLOCK_REALTIME)) == 0) {
    *dest = absl::InfinitePast();
  } else if (gpr_time_cmp(source, gpr_inf_future(GPR_CLOCK_REALTIME)) == 0) {
    *dest = absl::InfiniteFuture();
  } else {
    *dest = absl::UnixEpoch() + absl::Seconds(source.tv_sec) +
            absl::Nanoseconds(source.tv_nsec);
  }
  return absl::OkStatus();
}

Status FromAbslTime(absl::Time source, absl::Time *dest) {
  *dest = source;
  return absl::OkStatus();
}

Status FromAbslTime(absl::Time source, google::protobuf::Timestamp *dest) {
  auto maybe_seconds_nanos = ToSecondsNanos(source - absl::UnixEpoch());
  if (!maybe_seconds_nanos.has_value()) {
    return CannotRepresentError("absl::Time", "google::protobuf::Timestamp",
                                absl::FormatTime(source));
  }
  SecondsNanos seconds_nanos = maybe_seconds_nanos.value();
  // google::protobuf::Timestamp must have a non-negative |nanos| field.
  if (seconds_nanos.nanos < 0) {
    seconds_nanos.seconds -= 1;
    seconds_nanos.nanos += 1000000000;
  }
  if (!IsValidTimestampProto(seconds_nanos.seconds, seconds_nanos.nanos)) {
    return CannotRepresentError("absl::Time", "google::protobuf::Timestamp",
                                absl::FormatTime(source));
  }
  dest->set_seconds(seconds_nanos.seconds);
  dest->set_nanos(seconds_nanos.nanos);
  return absl::OkStatus();
}

Status FromAbslTime(absl::Time source, gpr_timespec *dest) {
  if (source == absl::InfinitePast()) {
    *dest = gpr_inf_past(GPR_CLOCK_REALTIME);
    return absl::OkStatus();
  }
  if (source == absl::InfiniteFuture()) {
    *dest = gpr_inf_future(GPR_CLOCK_REALTIME);
    return absl::OkStatus();
  }
  auto maybe_seconds_nanos = ToSecondsNanos(source - absl::UnixEpoch());
  if (!maybe_seconds_nanos.has_value()) {
    return CannotRepresentError("absl::Time", "gpr_timespec",
                                absl::FormatTime(source));
  }
  gpr_timespec time = gpr_time_add(
      gpr_time_from_seconds(maybe_seconds_nanos.value().seconds,
                            GPR_CLOCK_REALTIME),
      gpr_time_from_nanos(maybe_seconds_nanos.value().nanos, GPR_TIMESPAN));
  if (gpr_time_cmp(time, gpr_inf_past(GPR_CLOCK_REALTIME)) == 0 ||
      gpr_time_cmp(time, gpr_inf_future(GPR_CLOCK_REALTIME)) == 0) {
    return CannotRepresentError("absl::Time", "gpr_timespec",
                                absl::FormatTime(source));
  }
  *dest = time;
  return absl::OkStatus();
}

}  // namespace internal
}  // namespace asylo
