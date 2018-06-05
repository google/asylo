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

#include "asylo/platform/common/bridge_types.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "asylo/platform/common/test/bridge_types_test_data.h"
#include "asylo/test/util/enclave_test.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace {

class BridgeTypesTest : public EnclaveTest {
 protected:
  template <typename T>
  void RunTest(const std::string &input) {
    // Test that the trusted implementation meets this test's expectation.
    EnclaveInput enclave_input;
    SetEnclaveInputTestString(&enclave_input, input);
    EXPECT_THAT(client_->EnterAndRun(enclave_input, nullptr), IsOk());
    EXPECT_EQ(bridge_type_size(input), sizeof(T));
  }

 private:
  std::map<std::string, size_t> data_;
};

#define TEST_SIZE(T) \
  TEST_F(BridgeTypesTest, TestPackedSize_##T) { RunTest<T>(#T); }

TEST_SIZE(bridge_in_addr);
TEST_SIZE(bridge_in6_addr);
TEST_SIZE(bridge_sockaddr_in6);
TEST_SIZE(bridge_sockaddr_in);
TEST_SIZE(bridge_sockaddr_un);
TEST_SIZE(bridge_sockaddr);
TEST_SIZE(bridge_timeval);
TEST_SIZE(bridge_timespec);
TEST_SIZE(bridge_stat);
TEST_SIZE(bridge_pollfd);
#undef TEST_SIZE

}  // namespace
}  // namespace asylo
