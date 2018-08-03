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

#include "asylo/util/path.h"

#include <gtest/gtest.h>

namespace asylo {
namespace {

TEST(PathTest, JoinPathNoArgs) { EXPECT_EQ(JoinPath(), ""); }

TEST(PathTest, JoinPathOneArg) { EXPECT_EQ(JoinPath("foo"), "foo"); }

TEST(PathTest, JoinPathTwoArgsNoSlash) {
  EXPECT_EQ(JoinPath("foo", "bar"), "foo/bar");
}

TEST(PathTest, JoinPathTwoArgsWithFirstSlash) {
  EXPECT_EQ(JoinPath("foo/", "bar"), "foo/bar");
}

TEST(PathTest, JoinPathTwoArgsWithSecondSlash) {
  EXPECT_EQ(JoinPath("foo", "/bar"), "foo/bar");
}

TEST(PathTest, JoinPathTwoArgsWithWithTwoSlashes) {
  EXPECT_EQ(JoinPath("/foo/", "/bar/"), "/foo/bar/");
}

TEST(PathTest, JoinPathTwoArgsFirstEmpty) {
  EXPECT_EQ(JoinPath("foo", ""), "foo");
}

TEST(PathTest, JoinPathTwoArgsSecondEmpty) {
  EXPECT_EQ(JoinPath("", "bar"), "bar");
}

TEST(PathTest, JoinPathThreeArgsNoSlash) {
  EXPECT_EQ(JoinPath("foo", "bar", "baz"), "foo/bar/baz");
}

TEST(PathTest, JoinPathThreeArgsWithSlash) {
  EXPECT_EQ(JoinPath("/foo/", "/bar/", "/baz/"), "/foo/bar/baz/");
}

TEST(PathTest, JoinPathManyArgs1) {
  EXPECT_EQ(JoinPath("/foo/", "/bar/", "/baz/", "", "aa", "", "", "/ba/"),
            "/foo/bar/baz/aa/ba/");
}

TEST(PathTest, JoinPathManyArgs2) {
  EXPECT_EQ(JoinPath("/foo/", "/bar/", "/baz/", "/", "aa", "/", "/", "/ba/"),
            "/foo/bar/baz/aa/ba/");
}

}  // namespace
}  // namespace asylo
