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

#include "asylo/grpc/auth/util/safe_string.h"
#include <gtest/gtest.h>

namespace asylo {
namespace {

const char kString1[] = "foobar";
const size_t kString1Size = 6;

const char kString2[] = "hello world";
const size_t kString2Size = 11;

// This tests the C utility safe_string. The test methods test the
// safe_string_assign, safe_string_copy, and safe_string_free functions.
class SafeStringTest : public ::testing::Test {
 protected:
  void SetUp() override {
    safe_string_init(&s1_);
    safe_string_init(&s2_);
  }

  void TearDown() override {
    safe_string_free(&s1_);
    safe_string_free(&s2_);
  }

  safe_string s1_;
  safe_string s2_;
};

TEST_F(SafeStringTest, AssignOnce) {
  safe_string_assign(&s1_, kString1Size, kString1);
  EXPECT_EQ(kString1Size, s1_.size);
  EXPECT_EQ(0, memcmp(kString1, s1_.data, s1_.size));
}

TEST_F(SafeStringTest, ReassignLargerString) {
  safe_string_assign(&s1_, kString1Size, kString1);
  safe_string_assign(&s1_, kString2Size, kString2);
  EXPECT_EQ(kString2Size, s1_.size);
  EXPECT_EQ(0, memcmp(kString2, s1_.data, s1_.size));
}

TEST_F(SafeStringTest, ReassignSmallerString) {
  safe_string_assign(&s1_, kString2Size, kString2);
  safe_string_assign(&s1_, kString1Size, kString1);
  EXPECT_EQ(kString1Size, s1_.size);
  EXPECT_EQ(0, memcmp(kString1, s1_.data, s1_.size));
}

TEST_F(SafeStringTest, ReassignNull) {
  safe_string_assign(&s1_, kString1Size, kString1);
  safe_string_assign(&s1_, 0, nullptr);
  EXPECT_EQ(0, s1_.size);
  EXPECT_EQ(nullptr, s1_.data);
}

TEST_F(SafeStringTest, CopySmallerString) {
  safe_string_assign(&s1_, kString1Size, kString1);
  safe_string_assign(&s2_, kString2Size, kString2);
  safe_string_copy(/*dest=*/&s2_, /*src=*/&s1_);
  EXPECT_EQ(kString1Size, s2_.size);
  EXPECT_EQ(0, memcmp(kString1, s2_.data, s2_.size));
}

TEST_F(SafeStringTest, CopyLargerString) {
  safe_string_assign(&s1_, kString1Size, kString1);
  safe_string_assign(&s2_, kString2Size, kString2);
  safe_string_copy(/*dest=*/&s1_, /*src=*/&s2_);
  EXPECT_EQ(kString2Size, s1_.size);
  EXPECT_EQ(0, memcmp(kString2, s1_.data, s1_.size));
}

TEST_F(SafeStringTest, CopyNullString) {
  safe_string_assign(&s1_, 0, nullptr);
  safe_string_assign(&s2_, kString2Size, kString2);
  safe_string_copy(/*dest=*/&s2_, /*src=*/&s1_);
  EXPECT_EQ(0, s2_.size);
  EXPECT_EQ(nullptr, s2_.data);
}

TEST_F(SafeStringTest, Free) {
  safe_string_assign(&s1_, kString1Size, kString1);
  // The SafeStringTest::TearDown method will call safe_string_free again, but
  // it is safe to make multiple calls to safe_string_free on the same
  // safe_string.
  safe_string_free(&s1_);
  EXPECT_EQ(0, s1_.size);
  EXPECT_EQ(nullptr, s1_.data);
}

}  // namespace
}  // namespace asylo
