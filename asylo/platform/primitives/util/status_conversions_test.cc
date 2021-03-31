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
#include "absl/status/status.h"

using ::testing::Eq;

namespace asylo {
namespace primitives {
namespace {

// Validate members in Status set correctly during conversion.
TEST(StatusConversionsTest, ValidateStatus) {
  PrimitiveStatus reference_primitive_status{AbslStatusCode::kInternal,
                                             "some error message"};
  Status generated_status = MakeStatus(reference_primitive_status);

  EXPECT_THAT(static_cast<int>(generated_status.code()),
              Eq(reference_primitive_status.error_code()));
  EXPECT_THAT(generated_status.message(),
              Eq(reference_primitive_status.error_message()));
}

// Validate members in PrimitiveStatus set correctly when status has google
// error space.
TEST(StatusConversionsTest, PrimitiveStatusTestForStatusInGoogleError) {
  Status reference_asylo_status = absl::InternalError("some error message");
  PrimitiveStatus generated_primitive_status =
      MakePrimitiveStatus(reference_asylo_status);

  EXPECT_THAT(generated_primitive_status.error_code(),
              Eq(static_cast<int>(reference_asylo_status.code())));
  EXPECT_THAT(generated_primitive_status.error_message(),
              Eq(reference_asylo_status.message()));
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
