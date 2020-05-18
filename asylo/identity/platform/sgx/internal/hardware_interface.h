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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_HARDWARE_INTERFACE_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_HARDWARE_INTERFACE_H_

#include <cstdint>
#include <memory>

#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// Abstraction over the hardware APIs of the SGX platform. This interface
// collects all operations which depend on SGX-capable CPUs.
class HardwareInterface {
 public:
  // Constructs a default implementation of `HardwareInterface`, chosen at build
  // time, based on the toolchain. The implementation defaults to either a fake
  // with emulated routines or a real, hw-backed, impl.
  static std::unique_ptr<HardwareInterface> CreateDefault();

  virtual ~HardwareInterface() = default;

  // Gets the hardware key described by the input KEYREQUEST struct. The
  // function passes the input KEYREQUEST structure to the hardware without any
  // sanity checks, and consequently, the caller must ensure that this structure
  // well-formed. Additionally, the caller must ensure that the input KEYREQUEST
  // and HardwareKey structures are correctly aligned (as specified by the SGX
  // architecture). The caller can use the AlignedKeyrequestPtr and
  // AlignedHardwareKeyPtr objects to correctly align the input structures.
  virtual StatusOr<HardwareKey> GetKey(const Keyrequest &request) const = 0;

  // Gets the enclave REPORT using the EREPORT instruction. The input parameters
  // (tinfo and reportdata) as well as the output parameter (report) are passed
  // on directly to the hardware, and consequently, the caller must ensure that
  // these parameters are correctly aligned as specified by the SGX
  // architecture. The alignment can be achieved by using the appropriate
  // memory-aligned types defined in the file identity_key_management_structs.h.
  virtual StatusOr<Report> GetReport(const Targetinfo &tinfo,
                                     const Reportdata &reportdata) const = 0;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_HARDWARE_INTERFACE_H_
