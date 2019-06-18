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
#include "asylo/util/binary_search.h"

#include <limits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace asylo {
namespace {

TEST(BinarySearchTest, ConstantsSearchTest) {
  auto less_than_seventeen = [](size_t x) { return x < 17; };
  EXPECT_EQ(BinarySearch(less_than_seventeen), 16);
  auto always_false = [](size_t x) { return false; };
  EXPECT_EQ(BinarySearch(always_false), 0);
  auto less_than_one = [](size_t x) { return x < 1; };
  EXPECT_EQ(BinarySearch(less_than_one), 0);
  auto less_than_sixty_four = [](size_t x) { return x < 64; };
  EXPECT_EQ(BinarySearch(less_than_sixty_four), 63);
  auto less_than_a_lot = [](size_t x) { return x < 99999; };
  EXPECT_EQ(BinarySearch(less_than_a_lot), 99998);
  auto always_true = [](size_t x) { return true; };
  EXPECT_EQ(BinarySearch(always_true),
            std::numeric_limits<std::ptrdiff_t>::max());
}

}  // namespace
}  // namespace asylo
