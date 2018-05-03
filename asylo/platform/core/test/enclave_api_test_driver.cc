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

// This test creates an example EnclaveApiTest object, then packs it in
// EnclaveInput's Any type |input| field. The test enclave unpacks the proto and
// compares the transferred fields to the expected example values. Finally, the
// |output| protobuf is populated with example data inside the enclave, and then
// validated outside the enclave in the test driver.
class ClientApiTest : public EnclaveTest {};

TEST_F(ClientApiTest, InputOutputTest) {
  EnclaveInput enclave_input;
  EnclaveApiTest *input_test =
      enclave_input.MutableExtension(enclave_api_test_input);
  input_test->set_test_string("test string");
  input_test->set_test_int(1);
  input_test->add_test_repeated("test repeated 1");
  input_test->add_test_repeated("test repeated 2");
  EnclaveOutput enclave_output;
  Status status = client_->EnterAndRun(enclave_input, &enclave_output);
  EXPECT_THAT(status, IsOk());

  ASSERT_TRUE(enclave_output.HasExtension(enclave_api_test_output));
  EnclaveApiTest output_test =
      enclave_output.GetExtension(enclave_api_test_output);
  ASSERT_TRUE(output_test.has_test_string());
  ASSERT_TRUE(output_test.has_test_int());
  ASSERT_EQ(output_test.test_repeated_size(), 2);
  EXPECT_EQ(output_test.test_string(), "output string");
  EXPECT_EQ(output_test.test_int(), 1);
  EXPECT_EQ(output_test.test_repeated(0), "output repeated 1");
  EXPECT_EQ(output_test.test_repeated(1), "output repeated 2");
}

}  // namespace
}  // namespace asylo
