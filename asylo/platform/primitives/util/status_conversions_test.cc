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

#include "asylo/platform/primitives/util/status_conversions.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"

using ::testing::Eq;
using ::testing::StrEq;

namespace asylo {
namespace primitives {
namespace {

class StatusConversionsTest : public ::testing::Test {
 protected:
  enum NonGoogleError : int { OK = 0, NOT_OK = 1 };

  class NonGoogleErrorSpace : public error::ErrorSpace {
   public:
    std::string SpaceName() const override { return space_name_; }
    std::string String(int code) const override { return "OK"; }
    error::GoogleError GoogleErrorCode(int code) const override {
      return error::GoogleError::OK;
    }

    explicit NonGoogleErrorSpace() : space_name_{"non-google error space"} {}

    static ErrorSpace const *GetInstance() {
      static ErrorSpace const *instance = new NonGoogleErrorSpace();
      return instance;
    }

   private:
    const std::string space_name_;
  };

  const char *error_message_ = "some error message";

  error::ErrorSpace const *google_error_space_ =
      error::GoogleErrorSpace::GetInstance();

  PrimitiveStatus reference_primitive_status_{error::GoogleError::INTERNAL,
                                              error_message_};
  Status reference_google_error_status_ =
      Status(google_error_space_, error::GoogleError::INTERNAL, error_message_);
  Status reference_non_google_error_status_ =
      Status(NonGoogleErrorSpace::GetInstance(), NonGoogleError::NOT_OK,
             error_message_);
};

// Validate members in Status set correctly during conversion.
TEST_F(StatusConversionsTest, ValidateStatus) {
  Status generatedStatus = MakeStatus(reference_primitive_status_);

  EXPECT_THAT(generatedStatus.error_code(),
              Eq(reference_primitive_status_.error_code()));
  EXPECT_THAT(generatedStatus.error_space(), Eq(google_error_space_));
  EXPECT_THAT(generatedStatus.error_message(),
              Eq(reference_primitive_status_.error_message()));
}

// Validate members in PrimitiveStatus set correctly when status has google
// error space.
TEST_F(StatusConversionsTest, PrimitiveStatusTestForStatusInGoogleError) {
  PrimitiveStatus generatedPrimitiveStatus =
      MakePrimitiveStatus(reference_google_error_status_);
  EXPECT_THAT(generatedPrimitiveStatus.error_code(),
              Eq(reference_google_error_status_.error_code()));
  EXPECT_THAT(generatedPrimitiveStatus.error_message(),
              Eq(reference_google_error_status_.error_message()));
}

// Validate members in PrimitiveStatus set correctly when status has non google
// error space.
TEST_F(StatusConversionsTest, PrimitiveStatusTestForStatusNotInGoogleError) {
  PrimitiveStatus generatedPrimitiveStatus =
      MakePrimitiveStatus(reference_non_google_error_status_);

  EXPECT_THAT(generatedPrimitiveStatus.error_code(),
              Eq(error::GoogleError::OUT_OF_RANGE));
  EXPECT_THAT(std::string(generatedPrimitiveStatus.error_message()),
              StrEq(absl::StrCat(
                  "Could not convert error space '",
                  reference_non_google_error_status_.error_space()->SpaceName(),
                  "' to an asylo PrimitiveStatus: Unexpected error space. "
                  "Status dump: ",
                  reference_non_google_error_status_.ToString())));
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
