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

#ifndef ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_PARAMS_H_
#define ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_PARAMS_H_

#include <cstdint>

namespace asylo {

// Helper structure needed for passing 4 parameters to and from SGX layer
// in a single message, referred to as void *buffer.
struct SgxParams {
  // Serialized input parameters - if input != nullptr, input_size is its size,
  // otherwise input_size = 0.
  const void *input;
  uint64_t input_size;
  // Serialized results - if output != nullptr, output_size is its size,
  // otherwise output_size = 0.
  void *output;
  uint64_t output_size;
};

}  // namespace asylo
#endif  // ASYLO_PLATFORM_PRIMITIVES_SGX_SGX_PARAMS_H_
