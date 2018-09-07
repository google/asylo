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
#include <stdlib.h>
#include <unistd.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/test/util/test_flags.h"

namespace {

TEST(RealpathTest, SimpleNoBuf) {
  char *res_path = realpath("/tmp", nullptr);
  EXPECT_STREQ(res_path, "/tmp");
  free(res_path);
}

TEST(RealpathTest, SimpleBuf) {
  char buf[PATH_MAX];
  EXPECT_EQ(realpath("/tmp", buf), buf);
  EXPECT_STREQ(buf, "/tmp");
}

TEST(RealpathTest, ParentDir) {
  char *res_path = realpath("/tmp/../usr/../tmp", nullptr);
  EXPECT_STREQ(res_path, "/tmp");
  free(res_path);
}

}  // namespace
