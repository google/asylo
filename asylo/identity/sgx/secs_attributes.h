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

#ifndef ASYLO_IDENTITY_SGX_SECS_ATTRIBUTES_H_
#define ASYLO_IDENTITY_SGX_SECS_ATTRIBUTES_H_

#include <cstdint>
#include <cstring>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "asylo/identity/sgx/attributes.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// SGX defines 128 bits of enclave attributes, which are located in the SECS
// (Secure Enclave Control Structure) of the enclave. The low 64 bits of these
// attributes are treated as individual flags, whereas the upper 64 bits are
// collectively called XFRM (eXtended Feature Request Mask). The following enum
// defines the various attribute bits and assigns them a value that is same as
// their bit position in the SECS attributes bit vector. The names of these bits
// are taken verbatim from the Intel SDM (Software Developer's Manual).
enum class SecsAttributeBit {
  INIT = 0,       // Indicates whether the enclave has been
                  // initialized via EINIT instruction.
  DEBUG = 1,      // Indicates whether enclave is a debug enclave (=1)
                  // or a production enclave (=0).
  MODE64BIT = 2,  // Indicates whether the enclave is a 64-bit enclave
                  // (=1) or a 32-bit enclave (=0).
  // Bit 3 is an unused bit.
  PROVISIONKEY = 4,  // Indicates whether the enclave has access to the
                     // SGX provisioning key (=1) or not (=0).
  INITTOKENKEY = 5,  // Indicates whether the enclave has access to the
                     // INIT-token key (=1) or not (=0).
  // Bit 6 is an unused bit.
  KSS = 7,  // Indicates whether the enclave has support for Key
            // Separation and Sharing (KSS) (=1) or not (=0). Enabling KSS sets
            // the ISVEXTPRODID, ISVFAMILYID, CONFIGID and CONFIGSVN values in
            // an enclave's identity.
  // Bits 8 through 63 are unused.

  // XFRM bit positions. These mirror the bit positions in the x86-64 XCR0
  // register, and control two distinct-yet-related aspects of enclave
  // behavior. First, the values of these bits determine the value of XCR0
  // as seen by the enclave (determining whether the corresponding feature
  // is enabled inside the enclave or not). Second, the values of these bits
  // also determine whether the corresponding state is saved and cleared by
  // asynchronous enclave exit (AEX). Since the XFRM portion of the SECS
  // attributes starts at bit position 64 within the attributes field,
  // we add 64 to the XCR0 position. A detailed explanation of the various
  // capabilities controlled by these bits can be found in the Intel SDM vol 3.
  FPU = 64 + 0,        // Determines the behavior of the FPU/MMX capabilities.
  SSE = 64 + 1,        // Determines the behavior of the SSE capabilities.
  AVX = 64 + 2,        // Determines the behavior of certain AVX capabilities.
  BNDREG = 64 + 3,     // Determines the behavior of the MPX capabilities.
  BNDCSR = 64 + 4,     // Determines the behavior of the MPX capabilities.
  OPMASK = 64 + 5,     // Determines the behavior of certain AVX capabilities.
  ZMM_HI256 = 64 + 6,  // Determines the behavior of certain AVX capabilities.
  HI16_ZMM = 64 + 7,   // Determines the behavior of certain AVX capabilities.
  // Bit 64 + 8 is an unused bit
  PKRU = 64 + 9  // Determines the behavior of the Page Protection Keys.
};

// A structure representing a set of the ATTRIBUTES field of the SECS structure,
// as defined by the Intel SDM. This structure MUST be trivial, as it's expected
// to match the SDM type, bit-for-bit.
struct SecsAttributeSet {
  // Gets all attributes defined by the SGX architecture in an SecsAttributeSet
  // form.
  static SecsAttributeSet GetAllSupportedBits();

  // Gets attributes defined as must-be-set in an SecsAttributeSet form.
  static SecsAttributeSet GetMustBeSetBits();

  // Gets default "do not care" attributes in an SecsAttributeSet form.
  static SecsAttributeSet GetDefaultDoNotCareBits();

  // Gets the default attributes match mask, which is defined as the logical NOT
  // of the default "do not care" attributes.
  static SecsAttributeSet GetDefaultMask();

  // Sets the strictest match mask, which has all possible bits set to 1.
  static SecsAttributeSet GetStrictMask();

  // Converts a collection of SecsAttributeBit to a SecsAttributeSet.
  static StatusOr<SecsAttributeSet> FromBits(
      absl::Span<const SecsAttributeBit> attribute_list);

  SecsAttributeSet() = default;
  SecsAttributeSet(const SecsAttributeSet &) = default;
  SecsAttributeSet &operator=(const SecsAttributeSet &) = default;

  // Constructs a SecsAttributeSet object from |attributes|.
  explicit SecsAttributeSet(const Attributes &attributes);

  constexpr SecsAttributeSet(uint64_t flags_arg, uint64_t xfrm_arg)
      : flags(flags_arg), xfrm(xfrm_arg) {}

  // Clears all bits.
  void Clear();

  // Tests if an attribute bit in an SecsAttributeSet is set.
  bool IsSet(SecsAttributeBit attribute) const;

  // Convert this object into a protobuf Attributes message.
  Attributes ToProtoAttributes() const;

  uint64_t flags;
  uint64_t xfrm;
} ABSL_ATTRIBUTE_PACKED;

// All valid SecsAttributeBit values defined in the enumeration.
extern const SecsAttributeBit kAllSecsAttributeBits[15];

// Computes bitwise OR of two SecsAttributeSet values.
SecsAttributeSet operator|(const SecsAttributeSet &lhs,
                           const SecsAttributeSet &rhs);

// Computes bitwise OR of two SecsAttributeSet values, and overwrites |lhs| with
// the result.
SecsAttributeSet &operator|=(SecsAttributeSet &lhs,
                             const SecsAttributeSet &rhs);

// Computes bitwise AND of two SecsAttributeSet values.
SecsAttributeSet operator&(const SecsAttributeSet &lhs,
                           const SecsAttributeSet &rhs);

// Computes bitwise AND of two SecsAttributeSet values, and overwrites |lhs|
// with the result.
SecsAttributeSet &operator&=(SecsAttributeSet &lhs,
                             const SecsAttributeSet &rhs);

// Computes bitwise XOR of two SecsAttributeSet values.
SecsAttributeSet operator^(const SecsAttributeSet &lhs,
                           const SecsAttributeSet &rhs);

// Computes bitwise XOR of two SecsAttributeSet values, and overwrites |lhs|
// with the result.
SecsAttributeSet &operator^=(SecsAttributeSet &lhs,
                             const SecsAttributeSet &rhs);

// Computes bitwise negation of an SecsAttributeSet value.
SecsAttributeSet operator~(const SecsAttributeSet &value);

// Checks two SecsAttributeSet values for equality.
bool operator==(const SecsAttributeSet &lhs, const SecsAttributeSet &rhs);

// Checks two SecsAttributeSet values for inequality.
bool operator!=(const SecsAttributeSet &lhs, const SecsAttributeSet &rhs);

// Tests if an attribute bit in a Attributes proto is set.
bool IsAttributeSet(SecsAttributeBit attribute, const Attributes &attributes);

// Gets printable list of attributes from an SecsAttributeSet.
std::vector<absl::string_view> GetPrintableAttributeList(
    const Attributes &attributes);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_SECS_ATTRIBUTES_H_
