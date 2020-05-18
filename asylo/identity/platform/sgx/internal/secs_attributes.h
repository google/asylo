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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SECS_ATTRIBUTES_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SECS_ATTRIBUTES_H_

#include <cstdint>
#include <cstring>

#include "absl/base/attributes.h"
#include "absl/types/span.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

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

  // Converts a collection of AttributeBit to a SecsAttributeSet.
  static StatusOr<SecsAttributeSet> FromBits(
      absl::Span<const AttributeBit> attribute_list);

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
  bool IsSet(AttributeBit attribute) const;

  // Convert this object into a protobuf Attributes message.
  Attributes ToProtoAttributes() const;

  uint64_t flags;
  uint64_t xfrm;
} ABSL_ATTRIBUTE_PACKED;

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

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SECS_ATTRIBUTES_H_
