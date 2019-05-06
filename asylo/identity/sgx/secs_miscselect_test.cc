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

#include "asylo/identity/sgx/secs_miscselect.h"

#include <cstdint>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::ElementsAre;
using ::testing::IsEmpty;


TEST(SecsMiscselectTest, TestMiscselectBitInvalid) {
  uint32_t miscselect = 0;
  EXPECT_THAT(TestMiscselectBit(static_cast<SecsMiscselectBit>(32), miscselect)
                  .status(),
              StatusIs(asylo::error::INVALID_ARGUMENT));

  Miscselect miscselect_proto;
  miscselect_proto.set_value(miscselect);
  EXPECT_THAT(
      TestMiscselectBit(static_cast<SecsMiscselectBit>(32), miscselect_proto)
          .status(),
      StatusIs(asylo::error::INVALID_ARGUMENT));
}

TEST(SecsMiscselectTest, TestMiscselectBitFalse) {
  uint32_t miscselect = 0;
  EXPECT_THAT(TestMiscselectBit(SecsMiscselectBit::EXINFO, miscselect),
              IsOkAndHolds(false));

  Miscselect miscselect_proto;
  miscselect_proto.set_value(miscselect);
  EXPECT_THAT(TestMiscselectBit(SecsMiscselectBit::EXINFO, miscselect_proto),
              IsOkAndHolds(false));
}

TEST(SecsMiscselectTest, TestMiscselectBitTrue) {
  uint32_t miscselect = UINT32_C(1)
                        << static_cast<size_t>(SecsMiscselectBit::EXINFO);
  EXPECT_THAT(TestMiscselectBit(SecsMiscselectBit::EXINFO, miscselect),
              IsOkAndHolds(true));

  Miscselect miscselect_proto;
  miscselect_proto.set_value(miscselect);
  EXPECT_THAT(TestMiscselectBit(SecsMiscselectBit::EXINFO, miscselect_proto),
              IsOkAndHolds(true));
}

TEST(SecsMiscselectTest, GetPrintableMiscselectListEmpty) {
  uint32_t miscselect = 0;
  EXPECT_THAT(GetPrintableMiscselectList(miscselect), IsEmpty());

  Miscselect miscselect_proto;
  miscselect_proto.set_value(miscselect);
  EXPECT_THAT(GetPrintableMiscselectList(miscselect_proto), IsEmpty());
}

TEST(SecsMiscselectTest, GetPrintableMiscselectListNonempty) {
  uint32_t miscselect = UINT32_C(1)
                        << static_cast<size_t>(SecsMiscselectBit::EXINFO);
  EXPECT_THAT(GetPrintableMiscselectList(miscselect), ElementsAre("EXINFO"));

  Miscselect miscselect_proto;
  miscselect_proto.set_value(miscselect);
  EXPECT_THAT(GetPrintableMiscselectList(miscselect_proto),
              ElementsAre("EXINFO"));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
