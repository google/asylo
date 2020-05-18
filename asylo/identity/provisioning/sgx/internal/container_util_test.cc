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

#include "asylo/identity/provisioning/sgx/internal/container_util.h"

#include <limits>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/hash/hash_testing.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"

namespace asylo {
namespace sgx {
namespace {

CpuSvn CreateCpuSvn(absl::optional<absl::string_view> value) {
  CpuSvn cpu_svn;
  if (value.has_value()) {
    cpu_svn.set_value(value.value().data(), value.value().size());
  }
  return cpu_svn;
}

Fmspc CreateFmspc(absl::optional<absl::string_view> value) {
  Fmspc fmspc;
  if (value.has_value()) {
    fmspc.set_value(value.value().data(), value.value().size());
  }
  return fmspc;
}

PceSvn CreatePceSvn(absl::optional<uint32_t> value) {
  PceSvn pce_svn;
  if (value.has_value()) {
    pce_svn.set_value(value.value());
  }
  return pce_svn;
}

Tcb CreateTcb(absl::optional<absl::string_view> components,
              absl::optional<PceSvn> pce_svn) {
  Tcb tcb;
  if (components.has_value()) {
    tcb.set_components(components.value().data(), components.value().size());
  }
  if (pce_svn.has_value()) {
    *tcb.mutable_pce_svn() = pce_svn.value();
  }
  return tcb;
}

RawTcb CreateRawTcb(absl::optional<CpuSvn> cpu_svn,
                    absl::optional<PceSvn> pce_svn) {
  RawTcb tcbm;
  if (cpu_svn.has_value()) {
    *tcbm.mutable_cpu_svn() = cpu_svn.value();
  }
  if (pce_svn.has_value()) {
    *tcbm.mutable_pce_svn() = pce_svn.value();
  }
  return tcbm;
}

TEST(ContainerUtilTest, FmspcHashTest) {
  EXPECT_TRUE(absl::VerifyTypeImplementsAbslHashCorrectly(
      {CreateFmspc(absl::nullopt), CreateFmspc(""),
       CreateFmspc("The quick brown fox jumped over the lazy dog")},
      MessageEqual()));
}

TEST(ContainerUtilTest, TcbHashTest) {
  const absl::optional<std::string> kComponents[] = {
      absl::nullopt, "", "The quick brown fox jumped over the lazy dog"};
  const absl::optional<PceSvn> kPceSvns[] = {
      absl::nullopt, CreatePceSvn(absl::nullopt), CreatePceSvn(0),
      CreatePceSvn(std::numeric_limits<uint32_t>::max())};

  std::vector<Tcb> tcbs;
  for (const auto &components : kComponents) {
    for (const auto &pce_svn : kPceSvns) {
      tcbs.push_back(CreateTcb(components, pce_svn));
    }
  }

  EXPECT_TRUE(
      absl::VerifyTypeImplementsAbslHashCorrectly(tcbs, MessageEqual()));
}

TEST(ContainerUtilTest, RawTcbHashTest) {
  const absl::optional<CpuSvn> kCpuSvns[] = {
      absl::nullopt, CreateCpuSvn(""),
      CreateCpuSvn("The quick brown fox jumped over the lazy dog")};
  const absl::optional<PceSvn> kPceSvns[] = {
      absl::nullopt, CreatePceSvn(absl::nullopt), CreatePceSvn(0),
      CreatePceSvn(std::numeric_limits<uint32_t>::max())};

  std::vector<RawTcb> tcbms;
  for (const auto &cpu_svn : kCpuSvns) {
    for (const auto &pce_svn : kPceSvns) {
      tcbms.push_back(CreateRawTcb(cpu_svn, pce_svn));
    }
  }

  EXPECT_TRUE(
      absl::VerifyTypeImplementsAbslHashCorrectly(tcbms, MessageEqual()));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
