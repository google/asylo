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

#include "asylo/platform/system_call/serialize.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/platform/primitives/primitive_status.h"

namespace asylo {
namespace system_call {
namespace {

using testing::Eq;
using testing::StrEq;

TEST(SerializeTest, SerializeRequestInvalidSysnoTest) {
  const std::array<uint64_t, kParameterMax> parameters =
      std::array<uint64_t, 6>();
  primitives::PrimitiveStatus status =
      SerializeRequest(10000, parameters, nullptr);

  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  EXPECT_THAT(status.error_message(),
              StrEq(absl::StrCat(
                  "Could not infer system call descriptor from the sysno (",
                  10000, ") provided.")));
}

TEST(SerializeTest, SerializeResponseInvalidSysnoTest) {
  const std::array<uint64_t, kParameterMax> parameters =
      std::array<uint64_t, 6>();
  primitives::PrimitiveStatus status =
      SerializeResponse(10000, 0, 0, parameters, nullptr);

  EXPECT_THAT(status.error_code(),
              Eq(primitives::AbslStatusCode::kInvalidArgument));
  EXPECT_THAT(status.error_message(),
              StrEq(absl::StrCat(
                  "Could not infer system call descriptor from the sysno (",
                  10000, ") provided.")));
}

}  // namespace
}  // namespace system_call
}  // namespace asylo
