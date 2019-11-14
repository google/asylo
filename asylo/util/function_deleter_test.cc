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

#include "asylo/util/function_deleter.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/attributes.h"

namespace asylo {
namespace {

using ::testing::Eq;

ABSL_CONST_INIT int num_void_pointer_free_calls = 0;
void VoidPointerFree(void *ptr) { ++num_void_pointer_free_calls; }

ABSL_CONST_INIT int num_type_pointer_free_calls = 0;
void TypedPointerFree(char *ptr) { ++num_type_pointer_free_calls; }

TEST(FunctionDeleterTest, FunctionDeleter) {
  int addressable;
  { std::unique_ptr<int, FunctionDeleter<VoidPointerFree>> ptr(&addressable); }
  EXPECT_THAT(num_void_pointer_free_calls, Eq(1));
}

TEST(FunctionDeleterTest, TypedFunctionDeleter) {
  char addressable;
  {
    std::unique_ptr<char, TypedFunctionDeleter<char, TypedPointerFree>> ptr(
        &addressable);
  }
  EXPECT_THAT(num_type_pointer_free_calls, Eq(1));
}

}  // namespace
}  // namespace asylo
