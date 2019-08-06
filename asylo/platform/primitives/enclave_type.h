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

#ifndef ASYLO_PLATFORM_PRIMITIVES_ENCLAVE_TYPE_H_
#define ASYLO_PLATFORM_PRIMITIVES_ENCLAVE_TYPE_H_

namespace asylo {
namespace primitives {

// Architectures supported by the asylo primitive lib.
enum EnclaveType {
  UNKNOWN = 0,

  // SGX_HARDWARE describes an SGX enclave that is expected to run on an Intel
  // CPU with SGX capabilities.
  SGX_HARDWARE = 1,

  // SGX_SIMULATION describes an SGX Enclave that is expected to run in
  // simulation mode.
  SGX_SIMULATION = 2,

  // ASYLO_SIMULATION describes an Asylo simulation enclave.
  ASYLO_SIMULATION = 3,
};
}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_ENCLAVE_TYPE_H_
