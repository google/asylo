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

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/enclave.pb.h"
#include "asylo/platform/core/test/proto_test.pb.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

class EnclaveGetenvTest : public EnclaveTest {
 public:
  void SetUp() override {
    EnvironmentVariable *variable = config_.add_environment_variables();
    variable->set_name("GETENV_TEST");
    variable->set_value("expected_value");
    SetUpBase();
  }
};

TEST_F(EnclaveGetenvTest, GetenvTest) {
  EnclaveInput enclave_input;
  EnclaveApiTest enclave_input_test;
  enclave_input_test.add_test_repeated("GETENV_TEST=expected_value");
  enclave_input_test.add_test_repeated("PATH~");
  std::string buf = enclave_input_test.SerializeAsString();
  SetEnclaveInputTestString(&enclave_input, buf);
  Status status = client_->EnterAndRun(enclave_input, nullptr);
  EXPECT_THAT(status, IsOk());
}

}  // namespace
}  // namespace asylo
