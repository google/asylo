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

#ifndef ASYLO_PLATFORM_COMMON_TEST_BRIDGE_TYPES_TEST_DATA_H_
#define ASYLO_PLATFORM_COMMON_TEST_BRIDGE_TYPES_TEST_DATA_H_

#include <cstdint>
#include <string>

namespace asylo {

// Map a type name to its expected packed size. Used across enclave boundaries.
// Returns 0 when the type is unknown.
size_t bridge_type_size(const std::string &type_name);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_TEST_BRIDGE_TYPES_TEST_DATA_H_
