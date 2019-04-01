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

#include "asylo/identity/sgx/platform_provisioning.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/identity/sgx/platform_provisioning.pb.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

TEST(ProvisioningPlatformTest, PpidWithoutValueFieldIsInvalid) {
  EXPECT_THAT(ValidatePpid(Ppid()),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(ProvisioningPlatformTest, PpidWithValueFieldOfBadLengthIsInvalid) {
  Ppid ppid;
  *ppid.mutable_value() = "short";
  EXPECT_THAT(ValidatePpid(ppid),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  *ppid.mutable_value() = "waaaaaaaaaaaaaaaaaaaaaaaaaaytoolong";
  EXPECT_THAT(ValidatePpid(ppid),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(ProvisioningPlatformTest, ValidPpidIsValid) {
  Ppid ppid;
  *ppid.mutable_value() = "0123456789abcdef";
  ASYLO_EXPECT_OK(ValidatePpid(ppid));
}

TEST(ProvisioningPlatformTest, CpuSvnWithoutValueFieldIsInvalid) {
  EXPECT_THAT(ValidateCpuSvn(CpuSvn()),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(ProvisioningPlatformTest, CpuSvnWithValueFieldOfBadLengthIsInvalid) {
  CpuSvn cpu_svn;
  *cpu_svn.mutable_value() = "short";
  EXPECT_THAT(ValidateCpuSvn(cpu_svn),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));

  *cpu_svn.mutable_value() = "waaaaaaaaaaaaaaaaaaaaaaaaaaytoolong";
  EXPECT_THAT(ValidateCpuSvn(cpu_svn),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(ProvisioningPlatformTest, ValidCpuSvnIsValid) {
  CpuSvn cpu_svn;
  *cpu_svn.mutable_value() = "0123456789abcdef";
  ASYLO_EXPECT_OK(ValidateCpuSvn(cpu_svn));
}

TEST(PlatformProvisioningTest, PceSvnWithoutValueFieldIsInvalid) {
  EXPECT_THAT(ValidatePceSvn(PceSvn()),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PlatformProvisioningTest, PceSvnWithTooLargeValueFieldIsInvalid) {
  PceSvn pce_svn;
  pce_svn.set_value(100000);
  EXPECT_THAT(ValidatePceSvn(pce_svn),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PlatformProvisioningTest, ValidPceSvnIsValid) {
  PceSvn pce_svn;
  pce_svn.set_value(10000);
  ASYLO_EXPECT_OK(ValidatePceSvn(pce_svn));
}

TEST(PlatformProvisioningTest, PceIdWithoutValueFieldIsInvalid) {
  EXPECT_THAT(ValidatePceId(PceId()),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PlatformProvisioningTest, PceIdWithTooLargeValueFieldIsInvalid) {
  PceId pce_id;
  pce_id.set_value(100000);
  EXPECT_THAT(ValidatePceId(pce_id),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

TEST(PlatformProvisioningTest, ValidPceIdIsValid) {
  PceId pce_id;
  pce_id.set_value(10000);
  ASYLO_EXPECT_OK(ValidatePceId(pce_id));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
