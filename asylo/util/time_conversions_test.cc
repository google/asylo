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

#include "asylo/util/time_conversions.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <ostream>
#include <utility>
#include <vector>

#include "google/protobuf/duration.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include <google/protobuf/text_format.h>
#include <google/protobuf/util/time_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "asylo/util/logging.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/binary_search.h"
#include "asylo/util/time_conversions_internal.h"
#include "include/grpc/impl/codegen/gpr_types.h"
#include "include/grpc/support/time.h"

namespace asylo {
namespace {

using ::testing::Eq;
using ::testing::Matcher;
using ::testing::Test;
using ::testing::Types;

// Returns the minimum finite value of absl::Duration.
absl::Duration MinFiniteAbslDuration() {
  absl::Duration min = absl::Seconds(BinarySearch([](size_t seconds) {
    return seconds <= std::numeric_limits<int64_t>::max() &&
           absl::Seconds(-seconds) != -absl::InfiniteDuration();
  }));
  min -= absl::Nanoseconds(BinarySearch([min](size_t nanos) {
    return nanos <= 999999999 &&
           min - absl::Nanoseconds(nanos) != -absl::InfiniteDuration();
  }));
  return min;
}

// Returns the maximum finite value of absl::Duration.
absl::Duration MaxFiniteAbslDuration() {
  absl::Duration max = absl::Seconds(BinarySearch([](size_t seconds) {
    return seconds <= std::numeric_limits<int64_t>::max() &&
           absl::Seconds(seconds) != absl::InfiniteDuration();
  }));
  max += absl::Nanoseconds(BinarySearch([max](size_t nanos) {
    return nanos <= 999999999 &&
           max + absl::Nanoseconds(nanos) != absl::InfiniteDuration();
  }));
  return max;
}

// CHECK()s that |duration| is finite. Returns |duration|.
absl::Duration CheckFiniteAbslDuration(absl::Duration duration) {
  CHECK(duration != -absl::InfiniteDuration());
  CHECK(duration != absl::InfiniteDuration());
  return duration;
}

// Returns the minimum finite value of absl::Time.
absl::Time MinFiniteAbslTime() {
  absl::Time min = absl::UnixEpoch();
  min -= absl::Seconds(BinarySearch([min](size_t seconds) {
    return seconds <= std::numeric_limits<int64_t>::max() &&
           min - absl::Seconds(seconds) != absl::InfinitePast();
  }));
  min -= absl::Nanoseconds(BinarySearch([min](size_t nanos) {
    return nanos <= 999999999 &&
           min - absl::Nanoseconds(nanos) != absl::InfinitePast();
  }));
  return min;
}

// Returns the maximum finite value of absl::Time.
absl::Time MaxFiniteAbslTime() {
  absl::Time max = absl::UnixEpoch();
  max += absl::Seconds(BinarySearch([max](size_t seconds) {
    return seconds <= std::numeric_limits<int64_t>::max() &&
           max + absl::Seconds(seconds) != absl::InfiniteFuture();
  }));
  max += absl::Nanoseconds(BinarySearch([max](size_t nanos) {
    return nanos <= 999999999 &&
           max + absl::Nanoseconds(nanos) != absl::InfiniteFuture();
  }));
  return max;
}

// CHECK()s that |time| is finite. Returns |time|.
absl::Time CheckFiniteAbslTime(absl::Time time) {
  CHECK(time != absl::InfinitePast());
  CHECK(time != absl::InfiniteFuture());
  return time;
}

// Returns the minimum finite gpr_timespec with the given |clock_type| and the
// equivalent finite absl::Duration.
std::pair<gpr_timespec, absl::Duration> MinFiniteGprTimespecPair(
    gpr_clock_type clock_type) {
  int64_t seconds = -BinarySearch([clock_type](size_t negative_seconds) {
    return negative_seconds <= std::numeric_limits<int64_t>::max() &&
           gpr_time_cmp(gpr_time_from_seconds(-negative_seconds, clock_type),
                        gpr_inf_past(clock_type)) != 0;
  });
  gpr_timespec min = gpr_time_from_seconds(seconds, clock_type);
  int64_t nanos = -BinarySearch([clock_type, min](size_t negative_nanos) {
    return negative_nanos <= 999999999 &&
           gpr_time_cmp(gpr_time_add(min, gpr_time_from_nanos(-negative_nanos,
                                                              GPR_TIMESPAN)),
                        gpr_inf_past(clock_type)) != 0;
  });
  return {gpr_time_add(min, gpr_time_from_nanos(nanos, GPR_TIMESPAN)),
          CheckFiniteAbslDuration(absl::Seconds(seconds) +
                                  absl::Nanoseconds(nanos))};
}

// Returns the maximum finite gpr_timespec with the given |clock_type| and the
// equivalent finite absl::Duration.
std::pair<gpr_timespec, absl::Duration> MaxFiniteGprTimespecPair(
    gpr_clock_type clock_type) {
  int64_t seconds = BinarySearch([clock_type](size_t num_seconds) {
    return num_seconds <= std::numeric_limits<int64_t>::max() &&
           gpr_time_cmp(gpr_time_from_seconds(num_seconds, clock_type),
                        gpr_inf_future(clock_type)) != 0;
  });
  gpr_timespec max = gpr_time_from_seconds(seconds, clock_type);
  int64_t nanos = BinarySearch([clock_type, max](size_t num_nanos) {
    return num_nanos <= 999999999 &&
           gpr_time_cmp(
               gpr_time_add(max, gpr_time_from_nanos(num_nanos, GPR_TIMESPAN)),
               gpr_inf_future(clock_type)) != 0;
  });
  return {gpr_time_add(max, gpr_time_from_nanos(nanos, GPR_TIMESPAN)),
          CheckFiniteAbslDuration(absl::Seconds(seconds) +
                                  absl::Nanoseconds(nanos))};
}

// An equality matcher for gpr_timespec.
MATCHER_P(GprTimespecEquals, expected, "equals the expected gpr_timespec") {
  return gpr_time_cmp(arg, expected) == 0;
}

// A typed test fixture for conversions between duration type DurationT and
// absl::Duration. Each specialization must look like:
//
//     template <>
//     class TimeConversionsDurationTest<DurationT> : public Test {
//      public:
//       using ValueType = DurationT;
//
//       // Returns a vector of (ValueType, absl::Duration) pairs such that:
//       //
//       //   * internal::ToAbslDuration() should map the first element of each
//       //     pair to the second.
//       //   * internal::FromAbslDuration() should map the second element of
//       //     each pair to the first.
//       static std::vector<std::pair<ValueType, absl::Duration>> TestData();
//
//       // Returns a vector of ValueTypes such that internal::ToAbslDuration()
//       // should fail to convert each duration to absl::Duration with an
//       // INVALID_ARGUMENT error.
//       static std::vector<ValueType> InvalidTestData();
//
//       // Returns a vector of absl::Durations such that
//       // internal::FromAbslDuration() should fail to convert each duration to
//       // DurationT with an OUT_OF_RANGE error.
//       static std::vector<absl::Duration> OutOfRangeTestData();
//
//       // Returns a matcher that checks for equality between ValueTypes.
//       static Matcher<ValueType> Equals(ValueType duration);
//     };
template <typename DurationT>
class TimeConversionsDurationTest;

template <>
class TimeConversionsDurationTest<absl::Duration> : public Test {
 public:
  using ValueType = absl::Duration;

  static std::vector<std::pair<ValueType, absl::Duration>> TestData() {
    return {{-absl::InfiniteDuration(), -absl::InfiniteDuration()},
            {MinFiniteAbslDuration(), MinFiniteAbslDuration()},
            {absl::Seconds(-1000), absl::Seconds(-1000)},
            {absl::ZeroDuration(), absl::ZeroDuration()},
            {absl::Seconds(1000), absl::Seconds(1000)},
            {MaxFiniteAbslDuration(), MaxFiniteAbslDuration()},
            {absl::InfiniteDuration(), absl::InfiniteDuration()}};
  }

  static std::vector<ValueType> InvalidTestData() { return {}; }

  static std::vector<absl::Duration> OutOfRangeTestData() { return {}; }

  static Matcher<ValueType> Equals(ValueType duration) { return Eq(duration); }
};

template <>
class TimeConversionsDurationTest<google::protobuf::Duration> : public Test {
 public:
  using ValueType = google::protobuf::Duration;

  static std::vector<std::pair<ValueType, absl::Duration>> TestData() {
    return {{FromSecondsNanos(google::protobuf::util::TimeUtil::kDurationMinSeconds,
                              -999999999),
             CheckFiniteAbslDuration(
                 absl::Seconds(google::protobuf::util::TimeUtil::kDurationMinSeconds) +
                 absl::Nanoseconds(-999999999))},
            {FromSecondsNanos(google::protobuf::util::TimeUtil::kDurationMinSeconds, 0),
             absl::Seconds(google::protobuf::util::TimeUtil::kDurationMinSeconds)},
            {FromSecondsNanos(-1, 0), absl::Seconds(-1)},
            {FromSecondsNanos(0, -999999999), absl::Nanoseconds(-999999999)},
            {FromSecondsNanos(0, 0), absl::ZeroDuration()},
            {FromSecondsNanos(0, 999999999), absl::Nanoseconds(999999999)},
            {FromSecondsNanos(1, 0), absl::Seconds(1)},
            {FromSecondsNanos(google::protobuf::util::TimeUtil::kDurationMaxSeconds, 0),
             absl::Seconds(google::protobuf::util::TimeUtil::kDurationMaxSeconds)},
            {FromSecondsNanos(google::protobuf::util::TimeUtil::kDurationMaxSeconds,
                              999999999),
             CheckFiniteAbslDuration(
                 absl::Seconds(google::protobuf::util::TimeUtil::kDurationMaxSeconds) +
                 absl::Nanoseconds(999999999))}};
  }

  static std::vector<ValueType> InvalidTestData() {
    return {
        FromSecondsNanos(google::protobuf::util::TimeUtil::kDurationMinSeconds - 1, 0),
        FromSecondsNanos(-1, 1),
        FromSecondsNanos(0, -1000000000),
        FromSecondsNanos(0, 1000000000),
        FromSecondsNanos(1, -1),
        FromSecondsNanos(google::protobuf::util::TimeUtil::kDurationMaxSeconds + 1, 0)};
  }

  static std::vector<absl::Duration> OutOfRangeTestData() {
    return {-absl::InfiniteDuration(),
            MinFiniteAbslDuration(),
            absl::Seconds(google::protobuf::util::TimeUtil::kDurationMinSeconds - 1),
            absl::Seconds(google::protobuf::util::TimeUtil::kDurationMaxSeconds + 1),
            MaxFiniteAbslDuration(),
            absl::InfiniteDuration()};
  }

  static Matcher<ValueType> Equals(ValueType duration) {
    return EqualsProto(duration);
  }

 private:
  // Returns a google::protobuf::Duration with |seconds| seconds and |nanos|
  // nanoseconds. Does not validate the returned value.
  static google::protobuf::Duration FromSecondsNanos(int64_t seconds,
                                                     int32_t nanos) {
    google::protobuf::Duration duration;
    duration.set_seconds(seconds);
    duration.set_nanos(nanos);
    return duration;
  }
};

template <>
class TimeConversionsDurationTest<gpr_timespec> : public Test {
 public:
  using ValueType = gpr_timespec;

  static std::vector<std::pair<ValueType, absl::Duration>> TestData() {
    return {{gpr_inf_past(GPR_TIMESPAN), -absl::InfiniteDuration()},
            MinFiniteGprTimespecPair(GPR_TIMESPAN),
            {FromSecondsNanos(-1, 0), absl::Seconds(-1)},
            {FromSecondsNanos(0, -999999999), absl::Nanoseconds(-999999999)},
            {FromSecondsNanos(0, 0), absl::ZeroDuration()},
            {FromSecondsNanos(0, 999999999), absl::Nanoseconds(999999999)},
            {FromSecondsNanos(1, 0), absl::Seconds(1)},
            MaxFiniteGprTimespecPair(GPR_TIMESPAN),
            {gpr_inf_future(GPR_TIMESPAN), absl::InfiniteDuration()}};
  }

  static std::vector<ValueType> InvalidTestData() { return {}; }

  static std::vector<absl::Duration> OutOfRangeTestData() {
    return {
        CheckFiniteAbslDuration(MinFiniteGprTimespecPair(GPR_TIMESPAN).second -
                                absl::Nanoseconds(1)),
        CheckFiniteAbslDuration(MaxFiniteGprTimespecPair(GPR_TIMESPAN).second +
                                absl::Nanoseconds(1))};
  }

  static Matcher<ValueType> Equals(ValueType duration) {
    return GprTimespecEquals(duration);
  }

 private:
  // Returns a gpr_timespec of |clock_type| GPR_TIMESPAN with |seconds| seconds
  // and |nanos| nanoseconds.
  static gpr_timespec FromSecondsNanos(int64_t seconds, int32_t nanos) {
    gpr_timespec duration =
        gpr_time_add(gpr_time_from_seconds(seconds, GPR_TIMESPAN),
                     gpr_time_from_nanos(nanos, GPR_TIMESPAN));
    CHECK_NE(gpr_time_cmp(duration, gpr_inf_past(GPR_TIMESPAN)), 0);
    CHECK_NE(gpr_time_cmp(duration, gpr_inf_future(GPR_TIMESPAN)), 0);
    return duration;
  }
};

using DurationTypes =
    Types<absl::Duration, google::protobuf::Duration, gpr_timespec>;
TYPED_TEST_SUITE(TimeConversionsDurationTest, DurationTypes);

TYPED_TEST(TimeConversionsDurationTest, ValidConversionsToAbslDurationWork) {
  for (const auto &pair : TestFixture::TestData()) {
    absl::Duration absl_duration;
    ASYLO_ASSERT_OK(internal::ToAbslDuration(pair.first, &absl_duration));
    EXPECT_THAT(absl_duration, Eq(pair.second));
  }
}

TYPED_TEST(TimeConversionsDurationTest, ValidConversionsFromAbslDurationWork) {
  for (const auto &pair : TestFixture::TestData()) {
    TypeParam value_duration;
    ASYLO_ASSERT_OK(internal::FromAbslDuration(pair.second, &value_duration));
    EXPECT_THAT(value_duration, TestFixture::Equals(pair.first));
  }
}

TYPED_TEST(TimeConversionsDurationTest, InvalidConversionsToAbslDurationFail) {
  for (const TypeParam &value_duration : TestFixture::InvalidTestData()) {
    absl::Duration temp;
    EXPECT_THAT(internal::ToAbslDuration(value_duration, &temp),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TYPED_TEST(TimeConversionsDurationTest,
           OutOfRangeConversionsFromAbslDurationFail) {
  for (absl::Duration absl_duration : TestFixture::OutOfRangeTestData()) {
    typename TestFixture::ValueType temp;
    EXPECT_THAT(internal::FromAbslDuration(absl_duration, &temp),
                StatusIs(absl::StatusCode::kOutOfRange));
  }
}

TYPED_TEST(TimeConversionsDurationTest, RoundtripConversionsOfValidDataWork) {
  for (const auto &pair : TestFixture::TestData()) {
    EXPECT_THAT(ConvertDuration<TypeParam>(pair.first),
                IsOkAndHolds(TestFixture::Equals(pair.first)));
  }
}

TYPED_TEST(TimeConversionsDurationTest, RoundtripConversionsOfInvalidDataFail) {
  for (const TypeParam &value_duration : TestFixture::InvalidTestData()) {
    EXPECT_THAT(ConvertDuration<TypeParam>(value_duration),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

// A typed test fixture for conversions from time type TimeT to absl::Time and
// vice-versa. Each specialization must look like:
//
//     template <>
//     class TimeConversionsTimeTest<TimeT> : public Test {
//      public:
//       using ValueType = TimeT;
//
//       // Returns a vector of (ValueType, absl::Time) pairs such that:
//       //
//       //   * internal::ToAbslTime() should map the first element of each pair
//       //     to the second.
//       //   * internal::FromAbslTime() should map the second element of each
//       //     pair to the first.
//       static std::vector<std::pair<ValueType, absl::Time>> TestData();
//
//       // Returns a vector of ValueTypes such that internal::ToAbslTime()
//       // should fail to convert each time to absl::Time with an
//       // INVALID_ARGUMENT error.
//       static std::vector<ValueType> InvalidTestData();
//
//       // Returns a vector of absl::Times such that internal::FromAbslTime()
//       // should fail to convert each time to TimeT with an OUT_OF_RANGE
//       // error.
//       static std::vector<absl::Time> OutOfRangeTestData();
//
//       // Returns a matcher that checks for equality between ValueTypes.
//       static Matcher<ValueType> Equals(ValueType time);
//     };
template <typename TimeT>
class TimeConversionsTimeTest;

template <>
class TimeConversionsTimeTest<absl::Time> : public Test {
 public:
  using ValueType = absl::Time;

  static std::vector<std::pair<ValueType, absl::Time>> TestData() {
    return {{absl::InfinitePast(), absl::InfinitePast()},
            {MinFiniteAbslTime(), MinFiniteAbslTime()},
            {absl::UnixEpoch() - absl::Seconds(1000),
             absl::UnixEpoch() - absl::Seconds(1000)},
            {absl::UnixEpoch(), absl::UnixEpoch()},
            {absl::UnixEpoch() + absl::Seconds(1000),
             absl::UnixEpoch() + absl::Seconds(1000)},
            {MaxFiniteAbslTime(), MaxFiniteAbslTime()},
            {absl::InfiniteFuture(), absl::InfiniteFuture()}};
  }

  static std::vector<ValueType> InvalidTestData() { return {}; }

  static std::vector<absl::Time> OutOfRangeTestData() { return {}; }

  static Matcher<ValueType> Equals(ValueType time) { return Eq(time); }
};

template <>
class TimeConversionsTimeTest<google::protobuf::Timestamp> : public Test {
 public:
  using ValueType = google::protobuf::Timestamp;

  static std::vector<std::pair<ValueType, absl::Time>> TestData() {
    return {{FromSecondsNanos(google::protobuf::util::TimeUtil::kTimestampMinSeconds, 0),
             CheckFiniteAbslTime(
                 absl::UnixEpoch() +
                 absl::Seconds(google::protobuf::util::TimeUtil::kTimestampMinSeconds))},
            {FromSecondsNanos(google::protobuf::util::TimeUtil::kTimestampMinSeconds,
                              999999999),
             absl::UnixEpoch() +
                 absl::Seconds(google::protobuf::util::TimeUtil::kTimestampMinSeconds) +
                 absl::Nanoseconds(999999999)},
            {FromSecondsNanos(-1, 0), absl::UnixEpoch() - absl::Seconds(1)},
            {FromSecondsNanos(-1, 999999999),
             absl::UnixEpoch() - absl::Nanoseconds(1)},
            {FromSecondsNanos(0, 0), absl::UnixEpoch()},
            {FromSecondsNanos(0, 999999999),
             absl::UnixEpoch() + absl::Nanoseconds(999999999)},
            {FromSecondsNanos(1, 0), absl::UnixEpoch() + absl::Seconds(1)},
            {FromSecondsNanos(google::protobuf::util::TimeUtil::kTimestampMaxSeconds, 0),
             absl::UnixEpoch() +
                 absl::Seconds(google::protobuf::util::TimeUtil::kTimestampMaxSeconds)},
            {FromSecondsNanos(google::protobuf::util::TimeUtil::kTimestampMaxSeconds,
                              999999999),
             CheckFiniteAbslTime(
                 absl::UnixEpoch() +
                 absl::Seconds(google::protobuf::util::TimeUtil::kTimestampMaxSeconds) +
                 absl::Nanoseconds(999999999))}};
  }

  static std::vector<ValueType> InvalidTestData() {
    return {
        FromSecondsNanos(google::protobuf::util::TimeUtil::kTimestampMinSeconds - 1, 0),
        FromSecondsNanos(google::protobuf::util::TimeUtil::kTimestampMinSeconds - 1,
                         999999999),
        FromSecondsNanos(-1, -1), FromSecondsNanos(0, -1),
        FromSecondsNanos(0, 1000000000),
        // FromSecondsNanos(google::protobuf::util::TimeUtil::kTimestampMaxSeconds,
        // 1-999999999) is valid.
        FromSecondsNanos(google::protobuf::util::TimeUtil::kTimestampMaxSeconds + 1, 0)};
  }

  static std::vector<absl::Time> OutOfRangeTestData() {
    return {absl::InfinitePast(),
            absl::UnixEpoch() +
                absl::Seconds(google::protobuf::util::TimeUtil::kTimestampMinSeconds) -
                absl::Nanoseconds(1),
            // Values up to absl::UnixEpoch() +
            // absl::Seconds(google::protobuf::util::TimeUtil::kTimestampMaxSeconds) +
            // absl::Nanoseconds(999999999) are valid.
            absl::UnixEpoch() +
                absl::Seconds(google::protobuf::util::TimeUtil::kTimestampMaxSeconds + 1),
            absl::InfiniteFuture()};
  }

  static Matcher<ValueType> Equals(ValueType time) { return EqualsProto(time); }

 private:
  // Returns a google::protobuf::Timestamp with |seconds| seconds and |nanos|
  // nanoseconds. Does not validate the returned value.
  static google::protobuf::Timestamp FromSecondsNanos(int64_t seconds,
                                                      int32_t nanos) {
    google::protobuf::Timestamp time;
    time.set_seconds(seconds);
    time.set_nanos(nanos);
    return time;
  }
};

template <>
class TimeConversionsTimeTest<gpr_timespec> : public Test {
 public:
  using ValueType = gpr_timespec;

  static std::vector<std::pair<ValueType, absl::Time>> TestData() {
    return {{gpr_inf_past(GPR_CLOCK_REALTIME), absl::InfinitePast()},
            MinFiniteGprTimePair(),
            {FromSecondsNanos(-1, 0), absl::UnixEpoch() + absl::Seconds(-1)},
            {FromSecondsNanos(0, -999999999),
             absl::UnixEpoch() + absl::Nanoseconds(-999999999)},
            {FromSecondsNanos(0, 0), absl::UnixEpoch()},
            {FromSecondsNanos(0, 999999999),
             absl::UnixEpoch() + absl::Nanoseconds(999999999)},
            {FromSecondsNanos(1, 0), absl::UnixEpoch() + absl::Seconds(1)},
            MaxFiniteGprTimePair(),
            {gpr_inf_future(GPR_CLOCK_REALTIME), absl::InfiniteFuture()}};
  }

  static std::vector<ValueType> InvalidTestData() { return {}; }

  static std::vector<absl::Time> OutOfRangeTestData() {
    return {CheckFiniteAbslTime(MinFiniteGprTimePair().second -
                                absl::Nanoseconds(1)),
            CheckFiniteAbslTime(MaxFiniteGprTimePair().second +
                                absl::Nanoseconds(1))};
  }

  static Matcher<ValueType> Equals(ValueType duration) {
    return GprTimespecEquals(duration);
  }

 private:
  // Returns a pair of the minimum finite value of gpr_timespec with
  // |clock_type| GPR_CLOCK_REALTIME and an equivalent absl::Time.
  static std::pair<gpr_timespec, absl::Time> MinFiniteGprTimePair() {
    gpr_timespec min;
    absl::Duration min_absl;
    std::tie(min, min_absl) = MinFiniteGprTimespecPair(GPR_CLOCK_REALTIME);
    return {min, CheckFiniteAbslTime(absl::UnixEpoch() + min_absl)};
  }

  // Returns a pair of the maximum finite value of gpr_timespec with
  // |clock_type| GPR_CLOCK_REALTIME and an equivalent absl::Time.
  static std::pair<gpr_timespec, absl::Time> MaxFiniteGprTimePair() {
    gpr_timespec max;
    absl::Duration max_absl;
    std::tie(max, max_absl) = MaxFiniteGprTimespecPair(GPR_CLOCK_REALTIME);
    return {max, CheckFiniteAbslTime(absl::UnixEpoch() + max_absl)};
  }

  // Returns a gpr_timespec of |clock_type| GPR_CLOCK_REALTIME with |seconds|
  // seconds and |nanos| nanoseconds.
  static gpr_timespec FromSecondsNanos(int64_t seconds, int32_t nanos) {
    gpr_timespec time =
        gpr_time_add(gpr_time_from_seconds(seconds, GPR_CLOCK_REALTIME),
                     gpr_time_from_nanos(nanos, GPR_TIMESPAN));
    CHECK_NE(gpr_time_cmp(time, gpr_inf_past(GPR_CLOCK_REALTIME)), 0);
    CHECK_NE(gpr_time_cmp(time, gpr_inf_future(GPR_CLOCK_REALTIME)), 0);
    return time;
  }
};

using TimeTypes = Types<absl::Time, google::protobuf::Timestamp, gpr_timespec>;
TYPED_TEST_SUITE(TimeConversionsTimeTest, TimeTypes);

TYPED_TEST(TimeConversionsTimeTest, ValidConversionsToAbslTimeWork) {
  for (const auto &pair : TestFixture::TestData()) {
    absl::Time absl_time;
    ASYLO_ASSERT_OK(internal::ToAbslTime(pair.first, &absl_time));
    EXPECT_THAT(absl_time, Eq(pair.second));
  }
}

TYPED_TEST(TimeConversionsTimeTest, ValidConversionsFromAbslTimeWork) {
  for (const auto &pair : TestFixture::TestData()) {
    TypeParam value_time;
    ASYLO_ASSERT_OK(internal::FromAbslTime(pair.second, &value_time));
    EXPECT_THAT(value_time, TestFixture::Equals(pair.first));
  }
}

TYPED_TEST(TimeConversionsTimeTest, InvalidConversionsToAbslTimeFail) {
  for (const TypeParam &value_time : TestFixture::InvalidTestData()) {
    absl::Time temp;
    EXPECT_THAT(internal::ToAbslTime(value_time, &temp),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TYPED_TEST(TimeConversionsTimeTest, OutOfRangeConversionsFromAbslTimeFail) {
  for (absl::Time absl_time : TestFixture::OutOfRangeTestData()) {
    typename TestFixture::ValueType temp;
    EXPECT_THAT(internal::FromAbslTime(absl_time, &temp),
                StatusIs(absl::StatusCode::kOutOfRange));
  }
}

TYPED_TEST(TimeConversionsTimeTest, RoundtripConversionsOfValidDataWork) {
  for (const auto &pair : TestFixture::TestData()) {
    EXPECT_THAT(ConvertTime<TypeParam>(pair.first),
                IsOkAndHolds(TestFixture::Equals(pair.first)));
  }
}

TYPED_TEST(TimeConversionsTimeTest, RoundtripConversionsOfInvalidDataFail) {
  for (const TypeParam &value_time : TestFixture::InvalidTestData()) {
    EXPECT_THAT(ConvertTime<TypeParam>(value_time),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}
}  // namespace
}  // namespace asylo
