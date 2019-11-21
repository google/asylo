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

#include "asylo/util/url_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

TEST(UrlUtilTest, UrlDecode) {
  EXPECT_THAT(UrlDecode("a"), IsOkAndHolds("a"));
  EXPECT_THAT(UrlDecode("%3F"), IsOkAndHolds("?"));
  EXPECT_THAT(UrlDecode("quote%22_"), IsOkAndHolds("quote\"_"));
  EXPECT_THAT(UrlDecode("percent%25_"), IsOkAndHolds("percent%_"));
  EXPECT_THAT(UrlDecode("comma,_"), IsOkAndHolds("comma,_"));
  EXPECT_THAT(UrlDecode("tab%09_"), IsOkAndHolds("tab\t_"));
  EXPECT_THAT(UrlDecode("lf%0A_"), IsOkAndHolds("lf\n_"));
  EXPECT_THAT(UrlDecode("null%00_"), IsOkAndHolds(std::string("null\0_", 6)));
  EXPECT_THAT(UrlDecode(""), IsOkAndHolds(""));
  EXPECT_THAT(UrlDecode("http://foo.com/bar%23baz"),
              IsOkAndHolds("http://foo.com/bar#baz"));
  EXPECT_THAT(UrlDecode("abcDEF123-_.~!%27*()"),
              IsOkAndHolds("abcDEF123-_.~!'*()"));
  EXPECT_THAT(
      UrlDecode(
          "ABCDEFGHIJKLMNOPQRSTUZWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"),
      IsOkAndHolds("ABCDEFGHIJKLMNOPQRSTUZWXYZabcdefghijklmnopqrstuvwxyz0123456"
                   "789-_.~"));
}

}  // namespace
}  // namespace asylo
