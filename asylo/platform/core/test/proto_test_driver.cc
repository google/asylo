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

#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/platform/core/test/proto_test.pb.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

class EnclaveProtoTest : public EnclaveTest {};

TEST_F(EnclaveProtoTest, ReadWriteTest) {
  EnclaveInput enclave_input;
  EnclaveApiTest enclave_input_test;
  enclave_input_test.set_test_string("test string");
  enclave_input_test.set_test_int(1);
  enclave_input_test.add_test_repeated("test repeated 1");
  enclave_input_test.add_test_repeated("test repeated 2");
  std::string buf = enclave_input_test.SerializeAsString();
  SetEnclaveInputTestString(&enclave_input, buf);
  Status status = client_->EnterAndRun(enclave_input, nullptr);
  EXPECT_THAT(status, IsOk());
}

}  // namespace
}  // namespace asylo
