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

#include <array>
#include <memory>
#include <string>

#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "asylo/enclave_manager.h"
#include "asylo/platform/primitives/examples/hello_enclave.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/test/test_backend.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {
namespace test {

class HelloTest : public ::testing::Test {
 protected:
  // Loads an instance of a test enclave, aborting on failure.
  void SetUp() override {
    EnclaveManager::Configure(EnclaveManagerOptions());
    client_ = test::TestBackend::Get()->LoadTestEnclaveOrDie(
        /*enclave_name=*/"hello_test", absl::make_unique<DispatchTable>());
    ASYLO_EXPECT_OK(client_->exit_call_provider()->RegisterExitHandler(
       kExternalHelloHandler, ExitHandler{test_handler}));
  }

  void TearDown() override {
    ASYLO_EXPECT_OK(client_->Destroy());
  }

  std::shared_ptr<Client> client_;

 private:
  // When the enclave asks for it, send "Test"
  static Status test_handler(std::shared_ptr<Client> client, void *context,
                             NativeParameterStack *params) {
    static std::array<char, 4> test_data{{'T', 'e', 's', 't'}};
    // Push our message on to the parameter stack to pass to the enclave
    params->PushByCopy(Extent{test_data.data(), test_data.size()});
    return Status::OkStatus();
  }
};

TEST_F(HelloTest, Hello) {
  NativeParameterStack params;
  auto status = client_->EnclaveCall(kHelloEnclaveSelector, &params);
  EXPECT_FALSE(params.empty());
  auto message = params.Pop();
  EXPECT_TRUE(params.empty());
  const char *message_cstr = reinterpret_cast<const char *>(message->data());
  std::string message_string(message_cstr);
  EXPECT_THAT(message_string, ::testing::StrEq("Test, World!"));
  EXPECT_THAT(status, IsOk());
}

}  // namespace test
}  // namespace primitives
}  // namespace asylo
