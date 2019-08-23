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
#include <string>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"
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

// A structure representing a set of SECS attributes.
struct SecsAttributeSet {
  uint64_t flags;
  uint64_t xfrm;
} ABSL_ATTRIBUTE_PACKED;

// Converts an SecsAttributeBit list to an SecsAttributeSet.
StatusOr<SecsAttributeSet> MakeSecsAttributeSet(
    const std::vector<SecsAttributeBit> &attribute_list);

// Clears all bits of an SecsAttributeSet.
void ClearSecsAttributeSet(SecsAttributeSet *attributes);

// Computes bitwise OR of two SecsAttributeSet values.
SecsAttributeSet operator|(const SecsAttributeSet &lhs,
                           const SecsAttributeSet &rhs);

// Computes bitwise OR of two SecsAttributeSet values, and overwrites the lhs
// with the result.
SecsAttributeSet &operator|=(SecsAttributeSet &lhs,
                             const SecsAttributeSet &rhs);

// Computes bitwise AND of two SecsAttributeSet values.
SecsAttributeSet operator&(const SecsAttributeSet &lhs,
                           const SecsAttributeSet &rhs);

// Computes bitwise AND of two SecsAttributeSet values, and overwrites the lhs
// with the result.
SecsAttributeSet &operator&=(SecsAttributeSet &lhs,
                             const SecsAttributeSet &rhs);

// Computes bitwise negation of an SecsAttributeSet value.
SecsAttributeSet operator~(const SecsAttributeSet &value);

// Checks two SecsAttributeSet values for equality.
bool operator==(const SecsAttributeSet &lhs, const SecsAttributeSet &rhs);

// Checks two SecsAttributeSet values for inequality.
bool operator!=(const SecsAttributeSet &lhs, const SecsAttributeSet &rhs);

// Converts a list of SecsAttributeBit values to an SecsAttributeSet.
bool ConvertSecsAttributeRepresentation(
    const std::vector<SecsAttributeBit> &attribute_list,
    SecsAttributeSet *attributes);

// Converts an SecsAttributeSet to a list of SecsAttributeBit values.
bool ConvertSecsAttributeRepresentation(
    const SecsAttributeSet &attributes,
    std::vector<SecsAttributeBit> *attribute_list);

// Converts a list of SecsAttributeBit values to a
// Attributes proto.
bool ConvertSecsAttributeRepresentation(
    const std::vector<SecsAttributeBit> &attribute_list,
    Attributes *attributes);

// Convert a Attributes proto to a list of
// SecsAttributeBit values.
bool ConvertSecsAttributeRepresentation(
    const Attributes &attributes,
    std::vector<SecsAttributeBit> *attribute_list);

// Converts an SecsAttributeSet to a Attributes proto.
bool ConvertSecsAttributeRepresentation(const SecsAttributeSet &attributes_set,
                                        Attributes *attributes);

// Converts a Attributes proto to an SecsAttributeSet.
bool ConvertSecsAttributeRepresentation(const Attributes &attributes,
                                        SecsAttributeSet *attributes_set);

// Tests if an attribute bit in an SecsAttributeSet is set.
bool TestAttribute(SecsAttributeBit attribute,
                   const SecsAttributeSet &attributes_set);

// Tests if an attribute bit in a Attributes proto
// is set.
bool TestAttribute(SecsAttributeBit attribute, const Attributes &attributes);

// Gets all attributes defined by the SGX architecture in an SecsAttributeSet
// form.
bool GetAllSecsAttributes(SecsAttributeSet *attributes);

// Gets all attributes defined by the SGX architectrure in a Attributes form.
bool GetAllSecsAttributes(Attributes *attributes);

// Gets attributes defined as must-be-set in an SecsAttributeSet form.
bool GetMustBeSetSecsAttributes(SecsAttributeSet *attributes);

// Gets attributes defined as must-be-set in a Attributes form.
bool GetMustBeSetSecsAttributes(Attributes *attributes);

// Gets default "do not care" attributes in a list form.
bool GetDefaultDoNotCareSecsAttributes(
    std::vector<SecsAttributeBit> *attribute_list);

// Gets default "do not care" attributes in an SecsAttributeSet form.
bool GetDefaultDoNotCareSecsAttributes(SecsAttributeSet *attributes);

// Gets default "do not care" attributes in a Attributes form.
bool GetDefaultDoNotCareSecsAttributes(Attributes *attributes);

// Sets |attributes_match_mask| to the default attributes match mask, which is
// defined as the logical NOT of the default "do not care" attributes.
Status SetDefaultSecsAttributesMask(Attributes *attributes_match_mask);

// Sets |attributes_match_mask| to the strictest match mask, which sets all bits
// in the mask.
void SetStrictSecsAttributesMask(Attributes *attributes_match_mask);

// Gets printable list of attributes from a list of SecsAttributeBit values.
void GetPrintableAttributeList(
    const std::vector<SecsAttributeBit> &attribute_list,
    std::vector<absl::string_view> *printable_list);

// Gets printable list of attributes from an SecsAttributeSet.
void GetPrintableAttributeList(const SecsAttributeSet &attributes,
                               std::vector<absl::string_view> *printable_list);

// Gets printable list of attributes from a Attributes
// proto.
void GetPrintableAttributeList(const Attributes &attributes,
                               std::vector<absl::string_view> *printable_list);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_SECS_ATTRIBUTES_H_
