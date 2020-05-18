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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Not;

// Verify that VerifyHardwareReport() can verify a hardware report that is
// targeted at the verifying enclave.
TEST(VerifyHardwareReportTest, VerifyHardwareReportSucceedsWhenTargetIsSelf) {
  AlignedTargetinfoPtr targetinfo;
  SetTargetinfoFromSelfIdentity(targetinfo.get());

  AlignedReportdataPtr reportdata;
  reportdata->data = TrivialRandomObject<UnsafeBytes<kReportdataSize>>();

  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      report,
      HardwareInterface::CreateDefault()->GetReport(*targetinfo, *reportdata));
  ASYLO_ASSERT_OK(VerifyHardwareReport(report));
}

// Verify that VerifyHardwareReport() cannot verify a hardware report that is
// not targeted at the verifying enclave.
TEST(VerifyHardwareReportTest, VerifyHardwareReportFailsWhenTargetIsNotSelf) {
  AlignedTargetinfoPtr targetinfo;
  *targetinfo = TrivialZeroObject<Targetinfo>();

  AlignedReportdataPtr reportdata;
  reportdata->data = TrivialRandomObject<UnsafeBytes<kReportdataSize>>();

  Report report;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      report,
      HardwareInterface::CreateDefault()->GetReport(*targetinfo, *reportdata));
  ASSERT_THAT(VerifyHardwareReport(report), Not(IsOk()));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
