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

#ifndef ASYLO_IDENTITY_SGX_HARDWARE_INTERFACE_H_
#define ASYLO_IDENTITY_SGX_HARDWARE_INTERFACE_H_

#include <openssl/aes.h>

#include "absl/base/attributes.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {

// Gets the hardware key described by the input KEYREQUEST struct. The function
// passes the input KEYREQUEST structure to the hardware without any sanity
// checks, and consequently, the caller must ensure that this structure
// well-formed. Additionally, the caller must ensure that the input KEYREQUEST
// and HardwareKey structures are correctly aligned (as specified by the SGX
// architecture). The caller can use the AlignedKeyrequestPtr and
// AlignedHardwareKeyPtr objects to correctly align the input structures.
ABSL_MUST_USE_RESULT Status GetHardwareKey(const Keyrequest &request,
                                           HardwareKey *key);

// Gets the enclave REPORT using the EREPORT instruction. The input parameters
// (tinfo and reportdata) as well as the output parameter (report) are passed on
// directly to the hardware, and consequently, the caller must ensure that these
// parameters are correctly aligned as specified by the SGX architecture. The
// alignment can be achieved by using the appropriate memory-aligned types
// defined in the file identity_key_management_structs.h.
ABSL_MUST_USE_RESULT Status GetHardwareReport(const Targetinfo &tinfo,
                                              const Reportdata &reportdata,
                                              Report *report);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_HARDWARE_INTERFACE_H_
