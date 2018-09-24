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
#include "absl/types/span.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "gflags/gflags.h"
#include "asylo/util/logging.h"
#include "asylo/platform/arch/sgx/sgx_error_space.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/file_mapping.h"
#include "asylo/util/status.h"

DEFINE_string(enclave_path, "", "Path to enclave to load");

namespace asylo {
namespace {

constexpr char kEnclaveName[] = "enclave";

class LoadFromBufferTest : public ::testing::Test {
 public:
  LoadFromBufferTest() {
    EnclaveManager::Configure(EnclaveManagerOptions());
    manager_ = EnclaveManager::Instance().ValueOrDie();
  }

 protected:
  EnclaveManager *manager_;
};

// Tests that the enclave behaves normally when loaded from a buffer.
TEST_F(LoadFromBufferTest, ValidBufferCanBeLoaded) {
  auto create_from_file_result =
      FileMapping::CreateFromFile(FLAGS_enclave_path);
  ASSERT_THAT(create_from_file_result, IsOk());
  FileMapping enclave_file = std::move(create_from_file_result).ValueOrDie();

  SGXLoader loader(enclave_file.buffer(), /*debug=*/true);
  EnclaveConfig config;
  ASSERT_THAT(manager_->LoadEnclave(kEnclaveName, loader, config), IsOk());

  EnclaveClient *client = manager_->GetClient(kEnclaveName);
  EnclaveFinal final_input;
  EXPECT_THAT(manager_->DestroyEnclave(client, final_input), IsOk());
}

// Tests that the enclave fails to load from an invalid buffer.
TEST_F(LoadFromBufferTest, InvalidBufferFails) {
  SGXLoader loader(absl::Span<uint8_t>(), /*debug=*/true);
  EnclaveConfig config;

  Status load_status = manager_->LoadEnclave(kEnclaveName, loader, config);
  EXPECT_THAT(load_status, StatusIs(SGX_ERROR_INVALID_PARAMETER));
}

}  // namespace
}  // namespace asylo
