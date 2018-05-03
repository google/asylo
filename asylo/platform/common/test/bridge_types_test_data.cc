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

#include "asylo/platform/common/test/bridge_types_test_data.h"

#include <cstdint>
#include <string>

namespace asylo {

// Map a type name to its expected packed size. Used across enclave boundaries.
size_t bridge_type_size(const std::string &type_name) {
  if (type_name == "bridge_in_addr") {
    return 4;
  } else if (type_name == "bridge_in6_addr") {
    return 16;
  } else if (type_name == "bridge_sockaddr_in6") {
    return 26;
  } else if (type_name == "bridge_sockaddr_in") {
    return 14;
  } else if (type_name == "bridge_sockaddr_un") {
    return 108;
  } else if (type_name == "bridge_sockaddr") {
    return 110;
  } else if (type_name == "bridge_timeval") {
    return 16;
  } else if (type_name == "bridge_timespec") {
    return 16;
  } else if (type_name == "bridge_stat") {
    return 104;
  } else if (type_name == "bridge_pollfd") {
    return 8;
  } else {
    return 0;
  }
}

}  // namespace asylo
