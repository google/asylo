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
#include "asylo/platform/primitives/examples/hello_enclave.h"

#include <array>
#include <memory>
#include <string>

#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "gflags/gflags.h"
#include "asylo/platform/primitives/extent.h"
#include "asylo/platform/primitives/sim/untrusted_sim.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/dispatch_table.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

DEFINE_string(enclave_binary, "",
              "Path to the Sim enclave binary to be loaded");

namespace asylo {
namespace primitives {
namespace test {

class HelloTest : public ::testing::Test {
 public:
  // Loads an instance of a sim test enclave, aborting on failure.
  StatusOr<std::shared_ptr<Client>> LoadTestEnclave() {
    std::shared_ptr<Client> client;
    ASYLO_ASSIGN_OR_RETURN(
        client, LoadEnclave<SimBackend>(/*enclave_name=*/"hello_test",
                                        FLAGS_enclave_binary,
                                        absl::make_unique<DispatchTable>()));
    ASYLO_RETURN_IF_ERROR(client->exit_call_provider()->RegisterExitHandler(
        kExternalHelloHandler, ExitHandler{test_handler}));
    return client;
  }

  // Loads an instance of a sim test enclave, aborting on failure.
  std::shared_ptr<Client> LoadTestEnclaveOrDie() {
    auto result = LoadTestEnclave();
    EXPECT_THAT(result.status(), IsOk());
    return result.ValueOrDie();
  }

 private:
  // When the enclave asks for it, send "Test"
  static Status test_handler(std::shared_ptr<Client> client, void *context,
                             UntrustedParameterStack *params) {
    static std::array<char, 4> test_data{{'T', 'e', 's', 't'}};
    // Push our message on to the parameter stack to pass to the enclave
    params->PushByReference(Extent{test_data.data(), test_data.size()});
    return Status::OkStatus();
  }
};

TEST_F(HelloTest, Hello) {
  auto client = LoadTestEnclaveOrDie();

  UntrustedParameterStack params;
  auto status = client->EnclaveCall(kHelloEnclaveSelector, &params);
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
