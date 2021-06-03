/*
 *
 * Copyright 2017 Asylo authors
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

#include <iostream>

#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/client.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

using ::testing::Not;

// Placeholder client implementation for a debug enclave.
class TestClient : public EnclaveClient {
 public:
  TestClient() : EnclaveClient("test") {}

  Status EnterAndRun(const EnclaveInput &input,
                     EnclaveOutput *output) override {
    return absl::OkStatus();
  }

 private:
  Status EnterAndInitialize(const EnclaveConfig &config) override {
    return absl::OkStatus();
  }

  Status EnterAndFinalize(const EnclaveFinal &final_input) override {
    return absl::OkStatus();
  }

  Status DestroyEnclave() override { return absl::OkStatus(); }
};

// Loader which always fails for testing.
class FailingLoader : public EnclaveLoader {
 protected:
  StatusOr<std::unique_ptr<EnclaveClient>> LoadEnclave(
      absl::string_view name, void *base_address, const size_t enclave_size,
      const EnclaveConfig &config) const override {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Could not load enclave.");
  }

  EnclaveLoadConfig GetEnclaveLoadConfig() const override {
    EnclaveLoadConfig loader_config;
    return loader_config;
  }
};

// Loads clients by default constructing T.
template <typename T>
class FakeLoader : public EnclaveLoader {
 public:
  ~FakeLoader() override = default;

  FakeLoader() = default;

 protected:
  StatusOr<std::unique_ptr<EnclaveClient>> LoadEnclave(
      absl::string_view name, void *base_address, const size_t enclave_size,
      const EnclaveConfig &config) const override {
    return std::unique_ptr<EnclaveClient>(new T());
  }

  EnclaveLoadConfig GetEnclaveLoadConfig() const override {
    EnclaveLoadConfig loader_config;
    return loader_config;
  }
};

class LoaderTest : public ::testing::Test {
 protected:
  void SetUp() override {
    EnclaveManager::Configure(EnclaveManagerOptions());
    StatusOr<EnclaveManager *> manager_result = EnclaveManager::Instance();
    if (!manager_result.ok()) {
      LOG(FATAL) << manager_result.status();
    }
    manager_ = manager_result.value();
  }

  EnclaveManager *manager_;
  FakeLoader<TestClient> loader_;
};

// Basic overall test and demonstration of enclave lifecyle.
TEST_F(LoaderTest, Overall) {
  Status status = manager_->LoadEnclave("/fake", loader_);
  ASSERT_THAT(status, IsOk());

  EnclaveClient *client = manager_->GetClient("/fake");
  ASSERT_NE(client, nullptr);

  EnclaveInput einput;
  status = client->EnterAndRun(einput, nullptr);
  ASSERT_THAT(status, IsOk());

  EnclaveFinal efinal_input;
  status = manager_->DestroyEnclave(client, efinal_input);
  ASSERT_THAT(status, IsOk());
}

// Ensure an enclave name cannot be reused.
TEST_F(LoaderTest, DuplicateNamesFail) {
  Status status = manager_->LoadEnclave("/duplicate_names", loader_);
  ASSERT_THAT(status, IsOk());

  // Check we can't load another enclave with the same path.
  status = manager_->LoadEnclave("/duplicate_names", loader_);
  ASSERT_THAT(status, Not(IsOk()));
}

// Ensure we can not fetch a client for a destroyed enclave.
TEST_F(LoaderTest, FetchAfterDestroy) {
  Status status = manager_->LoadEnclave("/fetch_after_destroy", loader_);
  ASSERT_THAT(status, IsOk());

  auto client = manager_->GetClient("/fetch_after_destroy");
  ASSERT_NE(client, nullptr);

  EnclaveFinal final_input;
  status = manager_->DestroyEnclave(client, final_input);
  ASSERT_THAT(status, IsOk());

  // Check we can't fetch a client to a destroyed enclave.
  client = manager_->GetClient("/fetch_after_destroy");
  ASSERT_EQ(client, nullptr);
}

// Ensure that an error is reported on loading.
TEST_F(LoaderTest, PropagateLoaderFailure) {
  FailingLoader loader;
  auto status = manager_->LoadEnclave("/fake", loader);
  ASSERT_THAT(status, Not(IsOk()));
}

};  // namespace
};  // namespace asylo
