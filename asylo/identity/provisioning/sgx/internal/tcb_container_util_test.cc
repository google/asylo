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

#include "asylo/identity/provisioning/sgx/internal/tcb_container_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::SizeIs;

Tcb RandomTcb() {
  static absl::BitGen *tcb_generator = new absl::BitGen;

  Tcb tcb;
  tcb.mutable_components()->resize(kTcbComponentsSize);
  for (auto &byte : *tcb.mutable_components()) {
    uint8_t unsigned_byte = absl::Uniform<unsigned char>(*tcb_generator);
    byte = *reinterpret_cast<char *>(&unsigned_byte);
  }
  tcb.mutable_pce_svn()->set_value(absl::Uniform<uint32_t>(
      absl::IntervalClosedClosed, *tcb_generator, 0, kPceSvnMaxValue));
  return tcb;
}

RawTcb RandomRawTcb() {
  static absl::BitGen *raw_tcb_generator = new absl::BitGen;

  RawTcb tcbm;
  tcbm.mutable_cpu_svn()->mutable_value()->resize(kCpusvnSize);
  for (auto &byte : *tcbm.mutable_cpu_svn()->mutable_value()) {
    uint8_t unsigned_byte = absl::Uniform<unsigned char>(*raw_tcb_generator);
    byte = *reinterpret_cast<char *>(&unsigned_byte);
  }
  tcbm.mutable_pce_svn()->set_value(absl::Uniform<uint32_t>(
      absl::IntervalClosedClosed, *raw_tcb_generator, 0, kPceSvnMaxValue));
  return tcbm;
}

TEST(TcbHashersTest, TcbHashStressTest) {
#ifndef __ASYLO__
  constexpr int kNumItems = 100000;
#else   // __ASYLO__
  // Enclaves have a smaller heap.
  constexpr int kNumItems = 10000;
#endif  // __ASYLO__

  std::vector<Tcb> tcbs;
  tcbs.reserve(kNumItems);
  for (int i = 0; i < kNumItems; ++i) {
    tcbs.push_back(RandomTcb());
  }

  absl::flat_hash_set<Tcb, TcbHash, TcbEqual> tcbs_set;
  for (const Tcb &tcb : tcbs) {
    EXPECT_TRUE(tcbs_set.insert(tcb).second);
  }
  EXPECT_THAT(tcbs_set, SizeIs(kNumItems));

  for (const Tcb &tcb : tcbs) {
    EXPECT_TRUE(tcbs_set.contains(tcb));
  }
}

TEST(TcbHashersTest, RawTcbHashStressTest) {
#ifndef __ASYLO__
  constexpr int kNumItems = 100000;
#else   // __ASYLO__
  // Enclaves have a smaller heap.
  constexpr int kNumItems = 10000;
#endif  // __ASYLO__

  std::vector<RawTcb> tcbms;
  tcbms.reserve(kNumItems);
  for (int i = 0; i < kNumItems; ++i) {
    tcbms.push_back(RandomRawTcb());
  }

  absl::flat_hash_set<RawTcb, RawTcbHash, RawTcbEqual> tcbms_set;
  for (const RawTcb &tcbm : tcbms) {
    EXPECT_TRUE(tcbms_set.insert(tcbm).second);
  }
  EXPECT_THAT(tcbms_set, SizeIs(kNumItems));

  for (const RawTcb &tcbm : tcbms) {
    EXPECT_TRUE(tcbms_set.contains(tcbm));
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
