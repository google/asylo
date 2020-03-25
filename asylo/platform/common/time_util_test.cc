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

#include "asylo/platform/common/time_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {

namespace {

const int64_t kNanosecondsPerMicrosecond = 1000;

// Test converting between time formats.
TEST(TimeTests, Conversions) {
  std::vector<int64_t> values = {
      1,          -1,          0,         1,           573291173,  1088178268,
      869064257,  -3989335159, 36916388,  -1908624439, 1824021628, -407955685,
      2324227069, -1827186485, INT64_MAX, INT64_MIN,
  };

  // Timespec tests.
  for (int64_t value : values) {
    struct timespec ts;
    NanosecondsToTimeSpec(&ts, value);
    EXPECT_EQ(TimeSpecToNanoseconds(&ts), value);
    MicrosecondsToTimeSpec(&ts, value);
    EXPECT_EQ(TimeSpecToMicroseconds(&ts), value);
  }

  // Timeval tests.
  for (int64_t value : values) {
    struct timeval tv;
    NanosecondsToTimeVal(&tv, value);
    // TimeVal measures microseconds, so make our expectation precise to
    // microseconds.
    int64_t expectation = value - value % kNanosecondsPerMicrosecond;
    EXPECT_EQ(TimeValToNanoseconds(&tv), expectation);
    MicrosecondsToTimeVal(&tv, value);
    EXPECT_EQ(TimeValToMicroseconds(&tv), value);
  }
}

// Test of range checks.
TEST(TimeTests, Range) {
  // An int64 has range -2^63.. 2^63-1, so 1 << 63 is undefined.
  for (int i = 0; i < 63; i++) {
    struct timespec ts;
    ts.tv_sec = INT64_C(1) << i;
    EXPECT_EQ(IsRepresentableAsNanoseconds(&ts), i < 34);
    ts.tv_sec *= -1;
    EXPECT_EQ(IsRepresentableAsNanoseconds(&ts), i < 34);
  }

  for (int i = 0; i < 63; i++) {
    struct timeval tv;
    tv.tv_sec = INT64_C(1) << i;
    EXPECT_EQ(IsRepresentableAsNanoseconds(&tv), i < 34);
    tv.tv_sec *= -1;
    EXPECT_EQ(IsRepresentableAsNanoseconds(&tv), i < 34);
  }
}

TEST(TimeTests, TimeSpecSubtract) {
  timespec a, b, result;

  a.tv_sec = 5;
  a.tv_nsec = 700;
  b.tv_sec = 5;
  b.tv_nsec = 1200;
  ASSERT_TRUE(TimeSpecSubtract(a, b, &result));
  ASSERT_EQ(TimeSpecToNanoseconds(&result), -500);
  ASSERT_FALSE(TimeSpecSubtract(b, a, &result));
  ASSERT_EQ(TimeSpecToNanoseconds(&result), 500);

  a.tv_sec = 10;
  a.tv_nsec = 999999500;
  b.tv_sec = 11;
  b.tv_nsec = 800;
  ASSERT_TRUE(TimeSpecSubtract(a, b, &result));
  ASSERT_EQ(TimeSpecToNanoseconds(&result), -1300);
  ASSERT_FALSE(TimeSpecSubtract(b, a, &result));
  ASSERT_EQ(TimeSpecToNanoseconds(&result), 1300);

  a = b;
  ASSERT_FALSE(TimeSpecSubtract(a, b, &result));
  ASSERT_EQ(TimeSpecToNanoseconds(&result), 0);
  ASSERT_FALSE(TimeSpecSubtract(b, a, &result));
  ASSERT_EQ(TimeSpecToNanoseconds(&result), 0);
}

}  // namespace
}  // namespace asylo
