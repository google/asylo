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

#include <cstdint>
#include <map>
#include <string>

#include "asylo/platform/common/bridge_types.h"
#include "asylo/platform/common/test/bridge_types_test_data.h"
#include "asylo/test/util/enclave_test_application.h"


namespace asylo {

class EnclaveBridgeTypes : public EnclaveTestCase {
 public:
  EnclaveBridgeTypes() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    std::string test = GetEnclaveInputTestString(input);
    size_t size = bridge_type_size(test);
#define TEST_SIZE(T)                                                \
  if (test == #T) {                                                 \
    return (size == sizeof(T))                                      \
               ? Status::OkStatus()                                 \
               : Status(error::GoogleError::INTERNAL, "#T failed"); \
  }
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
    return Status(error::GoogleError::INVALID_ARGUMENT, "Unknown test type");
  }
};

TrustedApplication *BuildTrustedApplication() { return new EnclaveBridgeTypes; }

}  // namespace asylo
