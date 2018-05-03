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

#include <time.h>
#include <chrono>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {
namespace {

TEST(NanosleepTest, Nanosleep) {
  std::this_thread::sleep_for(std::chrono::seconds(1));
  struct timespec req;
  req.tv_sec = 0;
  req.tv_nsec = 1000000;  // 1ms
  EXPECT_FALSE(nanosleep(&req, nullptr));
}

}  // namespace
}  // namespace asylo
