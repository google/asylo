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

#include "absl/base/attributes.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include <openssl/aes.h>

namespace asylo {
namespace sgx {

// The SGX architecture defines the size of all hardware keys to be 128 bits
// (16 bytes), which is same as size of an AES block.
constexpr size_t kHardwareKeySize = AES_BLOCK_SIZE;

// Type alias used for holding a hardware key. It uses the SafeBytes
// template to ensure proper cleansing after the object goes out of scope.
using HardwareKey = SafeBytes<kHardwareKeySize>;

static_assert(sizeof(HardwareKey) == kHardwareKeySize,
              "Size of the struct HardwareKey is incorrect.");

// The SGX architecture requires that the output memory address passed into the
// EGETKEY instruction must be aligned on a 16-byte boundary.
using AlignedHardwareKeyPtr = AlignedObjectPtr<HardwareKey, 16>;

// Gets a 64-bit random number using the RDRAND instruction. The function
// attempts to obtain the desired entropy by executing the RDRAND instruction
// at most 10 times (as recommended by Intel). If the execution of RDRAND fails
// on all of those attempts, the function returns false, else the function
// true.
ABSL_MUST_USE_RESULT bool GetHardwareRand64(uint64_t *value);

// Gets the hardware key described by the input KEYREQUEST struct. The function
// passes the input KEYREQUEST structure to the hardware without any sanity
// checks, and consequently, the caller must ensure that this structure
// well-formed. Additionally, the caller must ensure that the input KEYREQUEST
// and HardwareKey structures are correctly aligned (as specified by the SGX
// architecture). The caller can use the AlignedKeyrequestPtr and
// AlignedHardwareKeyPtr objects to correctly align the input structures.
ABSL_MUST_USE_RESULT bool GetHardwareKey(const Keyrequest &request,
                                         HardwareKey *key);

// Gets the enclave REPORT using the EREPORT instruction. The input parameters
// (tinfo and reportdata) as well as the output parameter (report) are passed on
// directly to the hardware, and consequently, the caller must ensure that these
// parameters are correctly aligned as specified by the SGX architecture. The
// alignment can be achieved by using the appropriate memory-aligned types
// defined in the file identity_key_management_structs.h.
ABSL_MUST_USE_RESULT bool GetHardwareReport(const Targetinfo &tinfo,
                                            const Reportdata &reportdata,
                                            Report *report);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_HARDWARE_INTERFACE_H_
