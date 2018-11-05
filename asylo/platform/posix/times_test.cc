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

#include <sys/times.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {
namespace {

TEST(TimesTest, TimesIncrementing) {
  struct tms first_times;
  clock_t error_value = static_cast<clock_t>(-1);
  first_times.tms_utime = error_value;
  first_times.tms_stime = error_value;
  EXPECT_NE(times(&first_times), error_value);
  EXPECT_NE(first_times.tms_utime, error_value);
  EXPECT_NE(first_times.tms_stime, error_value);
  struct tms second_times;
  second_times.tms_utime = error_value;
  second_times.tms_stime = error_value;
  EXPECT_NE(times(&second_times), error_value);
  EXPECT_NE(second_times.tms_utime, error_value);
  EXPECT_NE(second_times.tms_stime, error_value);
  EXPECT_GE(second_times.tms_utime, first_times.tms_utime);
  EXPECT_GE(second_times.tms_stime, first_times.tms_stime);
}

}  // namespace
}  // namespace asylo
