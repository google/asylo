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

#include "asylo/util/error_space.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"

namespace asylo {
namespace error {
namespace {

// A test fixture is used for naming consistency and future scalability.
class ErrorSpaceTest : public ::testing::Test {};

// Make sure that the GoogleErrorSpace singleton can be retrieved based on the
// enum as well as the name, and that it returns the same value.
TEST_F(ErrorSpaceTest, GoogleErrorSpaceSingleton) {
  ErrorSpace const *space1 = ErrorSpace::Find(kCanonicalErrorSpaceName);
  EXPECT_NE(space1, nullptr);
  ErrorSpace const *space2 = error_enum_traits<GoogleError>::get_error_space();
  EXPECT_NE(space2, nullptr);
  ErrorSpace const *space3 =
      error_enum_traits<absl::StatusCode>::get_error_space();
  EXPECT_NE(space3, nullptr);
  EXPECT_EQ(space1, space2);
  EXPECT_EQ(space2, space3);
}

// Test the ErrorSpace interface for GoogleErrorSpace.
TEST_F(ErrorSpaceTest, GoogleErrorSpaceInterface) {
  ErrorSpace const *space = error_enum_traits<GoogleError>::get_error_space();
  EXPECT_EQ(space->SpaceName(), kCanonicalErrorSpaceName);

  EXPECT_EQ(space->String(GoogleError::OK), "OK");
  EXPECT_EQ(space->String(GoogleError::CANCELLED), "CANCELLED");
  EXPECT_EQ(space->String(GoogleError::UNKNOWN), "UNKNOWN");
  EXPECT_EQ(space->String(GoogleError::INVALID_ARGUMENT), "INVALID_ARGUMENT");
  EXPECT_EQ(space->String(GoogleError::DEADLINE_EXCEEDED), "DEADLINE_EXCEEDED");
  EXPECT_EQ(space->String(GoogleError::NOT_FOUND), "NOT_FOUND");
  EXPECT_EQ(space->String(GoogleError::ALREADY_EXISTS), "ALREADY_EXISTS");
  EXPECT_EQ(space->String(GoogleError::PERMISSION_DENIED), "PERMISSION_DENIED");
  EXPECT_EQ(space->String(GoogleError::RESOURCE_EXHAUSTED),
            "RESOURCE_EXHAUSTED");
  EXPECT_EQ(space->String(GoogleError::FAILED_PRECONDITION),
            "FAILED_PRECONDITION");
  EXPECT_EQ(space->String(GoogleError::ABORTED), "ABORTED");
  EXPECT_EQ(space->String(GoogleError::OUT_OF_RANGE), "OUT_OF_RANGE");
  EXPECT_EQ(space->String(GoogleError::UNIMPLEMENTED), "UNIMPLEMENTED");
  EXPECT_EQ(space->String(GoogleError::INTERNAL), "INTERNAL");
  EXPECT_EQ(space->String(GoogleError::UNAVAILABLE), "UNAVAILABLE");
  EXPECT_EQ(space->String(GoogleError::DATA_LOSS), "DATA_LOSS");
  EXPECT_EQ(space->String(GoogleError::UNAUTHENTICATED), "UNAUTHENTICATED");
  EXPECT_EQ(space->String(100), "Unrecognized Code (100)");

  for (int i = 0; i <= GoogleError::UNAUTHENTICATED; i++) {
    EXPECT_EQ(space->GoogleErrorCode(i), i);
  }
}

}  // namespace
}  // namespace error
}  // namespace asylo
