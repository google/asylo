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

#include "asylo/util/status_macros.h"

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

TEST(ReturnIfError, ReturnsOnErrorStatus) {
  auto func = []() -> Status {
    ASYLO_RETURN_IF_ERROR(absl::OkStatus());
    ASYLO_RETURN_IF_ERROR(absl::OkStatus());
    ASYLO_RETURN_IF_ERROR(Status(error::GoogleError::UNKNOWN, "EXPECTED"));
    return Status(error::GoogleError::UNKNOWN, "ERROR");
  };

  EXPECT_THAT(func(), StatusIs(error::GoogleError::UNKNOWN, "EXPECTED"));
}

TEST(ReturnIfError, ReturnsOnErrorStatusOr) {
  auto func = []() -> Status {
    ASYLO_RETURN_IF_ERROR(absl::OkStatus());
    ASYLO_RETURN_IF_ERROR(
        StatusOr<int>(Status(error::GoogleError::UNKNOWN, "EXPECTED")));
    return Status(error::GoogleError::UNKNOWN, "ERROR");
  };

  EXPECT_THAT(func(), StatusIs(error::GoogleError::UNKNOWN, "EXPECTED"));
}

TEST(ReturnIfError, ReturnsOnErrorFromLambda) {
  auto func = []() -> Status {
    ASYLO_RETURN_IF_ERROR([] { return absl::OkStatus(); }());
    ASYLO_RETURN_IF_ERROR(
        [] { return Status(error::GoogleError::UNKNOWN, "EXPECTED"); }());
    return Status(error::GoogleError::UNKNOWN, "ERROR");
  };

  EXPECT_THAT(func(), StatusIs(error::GoogleError::UNKNOWN, "EXPECTED"));
}

TEST(AssignOrReturn, AssignsMultipleVariablesInSequence) {
  auto func = []() -> Status {
    int value1;
    ASYLO_ASSIGN_OR_RETURN(value1, StatusOr<int>(1));
    EXPECT_EQ(1, value1);
    int value2;
    ASYLO_ASSIGN_OR_RETURN(value2, StatusOr<int>(2));
    EXPECT_EQ(2, value2);
    int value3;
    ASYLO_ASSIGN_OR_RETURN(value3, StatusOr<int>(3));
    EXPECT_EQ(3, value3);
    int value4;
    ASYLO_ASSIGN_OR_RETURN(
        value4, StatusOr<int>(Status(error::GoogleError::UNKNOWN, "EXPECTED")));
    return Status(error::GoogleError::UNKNOWN,
                  absl::StrCat("ERROR: assigned value ", value4));
  };

  EXPECT_THAT(func(), StatusIs(error::GoogleError::UNKNOWN, "EXPECTED"));
}

TEST(AssignOrReturn, AssignsRepeatedlyToSingleVariable) {
  auto func = []() -> Status {
    int value = 1;
    ASYLO_ASSIGN_OR_RETURN(value, StatusOr<int>(2));
    EXPECT_EQ(2, value);
    ASYLO_ASSIGN_OR_RETURN(value, StatusOr<int>(3));
    EXPECT_EQ(3, value);
    ASYLO_ASSIGN_OR_RETURN(
        value, StatusOr<int>(Status(error::GoogleError::UNKNOWN, "EXPECTED")));
    return Status(error::GoogleError::UNKNOWN, "ERROR");
  };

  EXPECT_THAT(func(), StatusIs(error::GoogleError::UNKNOWN, "EXPECTED"));
}

TEST(AssignOrReturn, MovesUniquePtr) {
  auto func = []() -> Status {
    std::unique_ptr<int> ptr;
    ASYLO_ASSIGN_OR_RETURN(
        ptr, StatusOr<std::unique_ptr<int>>(absl::make_unique<int>(1)));
    EXPECT_EQ(*ptr, 1);
    return Status(error::GoogleError::UNKNOWN, "EXPECTED");
  };

  EXPECT_THAT(func(), StatusIs(error::GoogleError::UNKNOWN, "EXPECTED"));
}

TEST(AssignOrReturn, DoesNotAssignUniquePtrOnErrorStatus) {
  auto func = []() -> Status {
    std::unique_ptr<int> ptr;
    ASYLO_ASSIGN_OR_RETURN(ptr, StatusOr<std::unique_ptr<int>>(Status(
                                    error::GoogleError::UNKNOWN, "EXPECTED")));
    EXPECT_EQ(ptr, nullptr);
    return absl::OkStatus();
  };

  EXPECT_THAT(func(), StatusIs(error::GoogleError::UNKNOWN, "EXPECTED"));
}

TEST(AssignOrReturn, MovesUniquePtrRepeatedlyToSingleVariable) {
  auto func = []() -> Status {
    std::unique_ptr<int> ptr;
    ASYLO_ASSIGN_OR_RETURN(
        ptr, StatusOr<std::unique_ptr<int>>(absl::make_unique<int>(1)));
    EXPECT_EQ(*ptr, 1);
    ASYLO_ASSIGN_OR_RETURN(
        ptr, StatusOr<std::unique_ptr<int>>(absl::make_unique<int>(2)));
    EXPECT_EQ(*ptr, 2);
    return Status(error::GoogleError::UNKNOWN, "EXPECTED");
  };

  EXPECT_THAT(func(), StatusIs(error::GoogleError::UNKNOWN, "EXPECTED"));
}

}  // namespace
}  // namespace asylo
