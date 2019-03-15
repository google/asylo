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
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_cat.h"
#include "asylo/platform/common/bridge_types.h"
#include "asylo/platform/common/test/bridge_types_test_data.h"
#include "asylo/test/util/enclave_test_application.h"

namespace asylo {

class EnclaveBridgeTypes : public EnclaveTestCase {
 public:
  EnclaveBridgeTypes() = default;

  Status Initialize(const EnclaveConfig &config) override {
    std::vector<std::pair<std::string, size_t>> sizes_list = {
        {"bridge_in_addr", sizeof(bridge_in_addr)},
        {"bridge_in6_addr", sizeof(bridge_in6_addr)},
        {"bridge_sockaddr_in6", sizeof(bridge_sockaddr_in6)},
        {"bridge_sockaddr_in", sizeof(bridge_sockaddr_in)},
        {"bridge_sockaddr_un", sizeof(bridge_sockaddr_un)},
        {"bridge_sockaddr", sizeof(bridge_sockaddr)},
        {"bridge_timeval", sizeof(bridge_timeval)},
        {"bridge_timespec", sizeof(bridge_timespec)},
        {"bridge_stat", sizeof(bridge_stat)},
        {"bridge_pollfd", sizeof(bridge_pollfd)},
    };
    absl::flat_hash_map<std::string, size_t> sizes(sizes_list.begin(),
                                                   sizes_list.end());
    type_sizes_ = std::move(sizes);
    return Status::OkStatus();
  }

  Status Run(const EnclaveInput &input, EnclaveOutput *output) override {
    std::string test_type = GetEnclaveInputTestString(input);
    size_t size = bridge_type_size(test_type);

    if (type_sizes_.find(test_type) == type_sizes_.end()) {
      return Status(error::GoogleError::INVALID_ARGUMENT, "Unknown test type");
    }
    if (type_sizes_[test_type] != size) {
      return Status(error::GoogleError::INTERNAL,
                    absl::StrCat(test_type, " failed"));
    }
    return Status::OkStatus();
  }

 private:
  absl::flat_hash_map<std::string, size_t> type_sizes_;
};

TrustedApplication *BuildTrustedApplication() { return new EnclaveBridgeTypes; }

}  // namespace asylo
