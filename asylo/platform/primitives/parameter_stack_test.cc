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

#include "asylo/platform/primitives/parameter_stack.h"
#include <algorithm>
#include <array>
#include <memory>
#include <vector>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/primitives/extent.h"

using ::testing::Eq;
using ::testing::StrEq;

namespace asylo {
namespace primitives {
namespace {

constexpr size_t kNumIterations = 64;
constexpr size_t kNumParams = 256;

TEST(ParameterStackTest, PushPopOwnedSpans) {
  ParameterStack<malloc, free> params;
  for (int32_t iter = 1; iter <= kNumIterations; ++iter) {
    EXPECT_TRUE(params.empty());
    EXPECT_EQ(params.size(), 0);
    for (int32_t i = 0; i < kNumParams; ++i) {
      *params.PushAlloc<int32_t>() = i * i;
    }
    EXPECT_FALSE(params.empty());
    EXPECT_EQ(params.size(), kNumParams);
    for (int32_t i = kNumParams; --i >= 0;) {
      EXPECT_THAT(params.Pop<int32_t>(), Eq(i * i));
    }
    EXPECT_TRUE(params.empty());
    EXPECT_EQ(params.size(), 0);
  }
}

TEST(ParameterStackTest, PushPopNotOwnedSpans) {
  ParameterStack<malloc, free> params;
  std::array<int32_t, kNumParams> values;
  for (int32_t iter = 1; iter <= kNumIterations; ++iter) {
    for (int32_t i = 0; i < kNumParams; ++i) {
      values[i] = i * i;
      params.PushByReference<int32_t>(values[i]);
    }
    EXPECT_FALSE(params.empty());
    EXPECT_EQ(params.size(), kNumParams);
    for (int32_t i = kNumParams; --i >= 0;) {
      EXPECT_THAT(params.Pop<int32_t>(), Eq(i * i));
    }
    EXPECT_TRUE(params.empty());
    EXPECT_EQ(params.size(), 0);
  }
}

TEST(ParameterStackTest, PushPopMixture) {
  ParameterStack<malloc, free> params;
  for (int32_t iter = 1; iter <= kNumIterations; ++iter) {
    // Push many parameters into an empty stack.
    EXPECT_TRUE(params.empty());
    EXPECT_EQ(params.size(), 0);
    for (int32_t i = 0; i < kNumParams; ++i) {
      *params.PushAlloc<int32_t>() = i * i;
    }
    // Pop some of them and verify. Leave 'iter' on the stack.
    EXPECT_FALSE(params.empty());
    EXPECT_EQ(params.size(), kNumParams);
    for (int32_t j = kNumParams; --j >= iter;) {
      EXPECT_THAT(params.Pop<int32_t>(), Eq(j * j));
    }
    // Push more parameters.
    EXPECT_FALSE(params.empty());
    EXPECT_EQ(params.size(), iter);
    for (int32_t i = 0; i < kNumParams; ++i) {
      *params.PushAlloc<int32_t>() = i * i;
    }
    // Pop all parameters and verify.
    EXPECT_FALSE(params.empty());
    EXPECT_EQ(params.size(), iter + kNumParams);
    for (int32_t i = kNumParams; --i >= 0;) {
      EXPECT_THAT(params.Pop<int32_t>(), Eq(i * i));
    }
    EXPECT_FALSE(params.empty());
    EXPECT_EQ(params.size(), iter);
    for (int32_t j = iter; --j >= 0;) {
      EXPECT_THAT(params.Pop<int32_t>(), Eq(j * j));
    }
    EXPECT_TRUE(params.empty());
    EXPECT_EQ(params.size(), 0);
  }
}

TEST(ParameterStackTest, PushAllocPointerCopyTest) {
  ParameterStack<malloc, free> params;

  for (int32_t iter = 1; iter <= kNumIterations; ++iter) {
    const char *buffer = "hello world";
    params.PushByCopy<char>(buffer, strlen(buffer) + 1);
    EXPECT_THAT(params.Top().As<char>(), StrEq(buffer));
    EXPECT_EQ(params.size(), iter);
  }
}

TEST(ParameterStackTest, PushCopyTest) {
  ParameterStack<malloc, free> params;

  for (int32_t iter = 1; iter <= kNumIterations; ++iter) {
    params.PushByCopy(Extent{&iter, sizeof(iter)});
    EXPECT_EQ(params.size(), iter);
  }
  for (int32_t iter = kNumIterations; iter >= 1; --iter) {
    EXPECT_THAT(params.Pop<int32_t>(), iter);
  }
  EXPECT_TRUE(params.empty());
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
