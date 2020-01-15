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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_ARCHITECTURE_BITS_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_ARCHITECTURE_BITS_H_

#include <cstddef>
#include <cstdint>

namespace asylo {
namespace sgx {

/// SGX defines 128 bits of enclave attributes, which are located in the SECS
/// (Secure Enclave Control Structure) of the enclave. The lower 64 bits of
/// these attributes are treated as individual flags, whereas the upper 64 bits
/// are collectively called XFRM (XSAVE Feature Request Mask). This enum defines
/// the various attribute bits and assigns them a value that is same as their
/// bit position in the SECS attributes bit vector. The names of these bits are
/// taken verbatim from the Intel SDM (Software Developer's Manual), volume 3D
/// (see https://software.intel.com/en-us/articles/intel-sdm).
enum class AttributeBit {
  /// Indicates whether the enclave has been initialized via EINIT instruction.
  INIT = 0,

  /// Indicates whether the enclave is a debug (1) or production (0) enclave.
  DEBUG = 1,

  /// Indicates whether the enclave is a 64-bit (1) or a 32-bit (0) enclave.
  MODE64BIT = 2,

  // Bit 3 is an unused bit.

  /// Indicates whether the enclave has access to the SGX provisioning key (1)
  /// or not (0).
  PROVISIONKEY = 4,

  /// Indicates whether the enclave has access to the INIT-token key (1) or not
  /// (0).
  INITTOKENKEY = 5,

  // Bit 6 is an unused bit.

  /// Indicates whether the enclave has support for Key Separation and Sharing
  /// (KSS) (1) or not (0). Enabling KSS sets the ISVEXTPRODID, ISVFAMILYID,
  /// CONFIGID and CONFIGSVN values in an enclave's identity.
  KSS = 7,

  // Bits 8 through 63 are unused.

  // XFRM bit positions. These mirror the bit positions in the x86-64 XCR0
  // register, and control two distinct-yet-related aspects of enclave
  // behavior. First, the values of these bits determine the value of XCR0 as
  // seen by the enclave (determining whether the corresponding feature is
  // enabled inside the enclave or not). Second, the values of these bits also
  // determine whether the corresponding state is saved and cleared by
  // asynchronous enclave exit (AEX). Since the XFRM portion of the SECS
  // attributes starts at bit position 64 within the attributes field, we add 64
  // to the XCR0 position. A detailed explanation of the various capabilities
  // controlled by these bits can be found in the Intel SDM, volume 3D.

  /// Determines the behavior of the FPU/MMX capabilities.
  FPU = 64 + 0,

  /// Determines the behavior of the SSE capabilities.
  SSE = 64 + 1,

  /// Determines the behavior of certain AVX capabilities.
  AVX = 64 + 2,

  /// Determines the behavior of the MPX capabilities.
  BNDREG = 64 + 3,

  /// Determines the behavior of the MPX capabilities.
  BNDCSR = 64 + 4,

  /// Determines the behavior of certain AVX capabilities.
  OPMASK = 64 + 5,

  /// Determines the behavior of certain AVX capabilities.
  ZMM_HI256 = 64 + 6,

  /// Determines the behavior of certain AVX capabilities.
  HI16_ZMM = 64 + 7,

  // Bit 64 + 8 is an unused bit

  /// Determines the behavior of the Page Protection Keys.
  PKRU = 64 + 9
};

/// All valid bit positions in the ATTRIBUTES bit vector.
extern const AttributeBit kAllAttributeBits[15];

/// The number of ATTRIBUTES flag bits.
extern const size_t kNumAttributeFlagBits;

/// The number of ATTRIBUTES XFRM bits.
extern const size_t kNumAttributeXfrmBits;

/// The total number of ATTRIBUTES bits.
extern const size_t kNumAttributeBits;

/// A bitmask over all valid ATTRIBUTES flag bits.
extern const uint64_t kValidAttributeFlagsBitmask;

/// A bitmask over all valid ATTRIBUTES XFRM bits.
extern const uint64_t kValidAttributeXfrmBitmask;

/// The following enum defines the various MISCSELECT bits and assigns them a
/// value that is same as their bit position in the SECS MISCSELECT bit vector.
/// The names of these bits are taken verbatim from the Intel SDM (Software
/// Developer's Manual).
enum class MiscselectBit {
  /// Indicates that information about page faults and GP exceptions that
  /// occurred inside an enclave will be saved upon an asynchronous exit.
  EXINFO = 0,
};

/// All valid bit positions in the MISCSELECT bit vector.
extern const MiscselectBit kAllMiscselectBits[1];

/// The total number of MISCSELECT bits.
extern const size_t kNumMiscselectBits;

/// A bitmask over all valid MISCSELECT bits.
extern const uint32_t kValidMiscselectBitmask;

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_ARCHITECTURE_BITS_H_
