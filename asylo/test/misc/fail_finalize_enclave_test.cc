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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/client.h"
#include "asylo/enclave_manager.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

using ::testing::Not;

constexpr char kEnclaveName[] = "enclave";
constexpr char kClientName[] = "client";

TEST(FailFinalizeEnclaveTest, FailFinalize) {
  ASYLO_ASSERT_OK(EnclaveManager::Configure(EnclaveManagerOptions()));

  EnclaveManager *manager;
  ASYLO_ASSERT_OK_AND_ASSIGN(manager, EnclaveManager::Instance());

  SimEmbeddedLoader loader(kEnclaveName, /*debug=*/true);
  EnclaveConfig config;
  ASYLO_ASSERT_OK(manager->LoadEnclave(kClientName, loader, config));

  auto client = manager->GetClient(kClientName);
  EnclaveFinal final_proto;
  EXPECT_THAT(manager->DestroyEnclave(client, final_proto), Not(IsOk()));
}

}  // namespace
}  // namespace asylo
