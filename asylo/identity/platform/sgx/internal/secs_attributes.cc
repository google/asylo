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

#include "asylo/identity/platform/sgx/internal/secs_attributes.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>

#include "absl/base/macros.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "asylo/util/logging.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"

namespace asylo {
namespace sgx {
namespace {

// DoNotCare attribute bits.
// The following XFRM attributes are *generally* considered as not affecting
// the security of the enclave, and are ignored during attestation
// verification and seal-key derivation by default. Enclave writers can
// override these lists during their invocation of the enclave-identity
// libraries.
//
// Rationale for inclusion/exclusion in/from the list:
// ===================================================
// The XFRM attribute determine the availability of the
// corresponding instruction-set features inside an enclave. For features
// included in the following list, the x86-64 architecture provides fail-closed
// semantics. That is, if the enclave tries to use a feature when the
// corresponding bit is not set, the enclave gets a #UD exception, which cannot
// be hidden from an enclave by the in-scope adversaries. On the other hand,
// setting the bit when the enclave is not intending to use the feature does not
// affect the enclave in any meaningful way.
//
// MPX, on the other hand, when enabled, turns some of the legacy NOP
// instructions into memory-write operations. Consequently, it can be used
// as an attack vector against enclaves that are written (or that rely on
// libraries that are written) without knowledge of MPX. Consequently, MPX
// bits are not included in the following list.
//
// Finally, page-protection keys allow an application to partition its own
// address space into security domains, and if an adversary turns off this
// feature without the enclave's knowledge, such a behavior *could* adversely
// affect the enclave's security. Consequently, the PKRU bit is not included
// in the following list.
//
// There are (somewhat contrived) cases where enclave writers may want to
// assign different security properties to their enclave depending on
// whether their enclave is using features included in the following list
// (e.g., due to potentially different side-channel behavior, an enclave
// writer may want to consider code paths that use AVX to be more trustworthy
// than those that do not use AVX). In such situations, enclave writers can
// override this list through the enclave-identity library.
constexpr AttributeBit kDefaultDoNotCareSecsAttributes[] = {
    AttributeBit::FPU,    AttributeBit::SSE,       AttributeBit::AVX,
    AttributeBit::OPMASK, AttributeBit::ZMM_HI256, AttributeBit::HI16_ZMM};

// Must-be-one attribute bits
constexpr AttributeBit kMustBeSetAttributes[] = {
    AttributeBit::INIT, AttributeBit::FPU, AttributeBit::SSE};

}  // namespace

SecsAttributeSet SecsAttributeSet::GetAllSupportedBits() {
  static const SecsAttributeSet set =
      SecsAttributeSet::FromBits(kAllAttributeBits).value();
  return set;
}

SecsAttributeSet SecsAttributeSet::GetMustBeSetBits() {
  static const SecsAttributeSet set =
      SecsAttributeSet::FromBits(kMustBeSetAttributes).value();
  return set;
}

SecsAttributeSet SecsAttributeSet::GetDefaultDoNotCareBits() {
  static const SecsAttributeSet set =
      SecsAttributeSet::FromBits(kDefaultDoNotCareSecsAttributes).value();
  return set;
}

SecsAttributeSet SecsAttributeSet::GetDefaultMask() {
  return ~GetDefaultDoNotCareBits();
}

SecsAttributeSet SecsAttributeSet::GetStrictMask() {
  return {std::numeric_limits<uint64_t>::max(),
          std::numeric_limits<uint64_t>::max()};
}

StatusOr<SecsAttributeSet> SecsAttributeSet::FromBits(
    absl::Span<const AttributeBit> attribute_list) {
  SecsAttributeSet attributes = {};
  for (AttributeBit attribute : attribute_list) {
    size_t bit_position = static_cast<size_t>(attribute);
    if (bit_position >= kNumAttributeBits) {
      return Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrFormat("SecsAttributeBit specifies a bit position %d "
                          " that is larger than the max allowed value of %d",
                          bit_position, kNumAttributeBits - 1));
    }
    if (bit_position < kNumAttributeFlagBits) {
      attributes.flags |= (1ULL << bit_position);
    } else {
      attributes.xfrm |= (1ULL << (bit_position - kNumAttributeFlagBits));
    }
  }
  return attributes;
}

SecsAttributeSet::SecsAttributeSet(const Attributes &attributes)
    : SecsAttributeSet(attributes.flags(), attributes.xfrm()) {}

void SecsAttributeSet::Clear() {
  flags = 0;
  xfrm = 0;
}

bool SecsAttributeSet::IsSet(AttributeBit attribute) const {
  size_t bit_position = static_cast<size_t>(attribute);
  if (bit_position >= kNumAttributeBits) {
    // The only way this can happen is if someone does some funny business with
    // integer casting instead of using SecsAttributeBit values as an input.
    LOG(ERROR) << "SecsAttributeBit specifies a bit position " << bit_position
               << " that is larger than the max allowed value of "
               << kNumAttributeBits - 1;
    return false;
  }

  if (bit_position < kNumAttributeFlagBits) {
    return flags & (1ULL << bit_position);
  } else {
    return xfrm & (1ULL << (bit_position - kNumAttributeFlagBits));
  }
}

Attributes SecsAttributeSet::ToProtoAttributes() const {
  Attributes attributes;
  attributes.set_flags(flags);
  attributes.set_xfrm(xfrm);
  return attributes;
}

SecsAttributeSet operator|(const SecsAttributeSet &lhs,
                           const SecsAttributeSet &rhs) {
  SecsAttributeSet result;
  result.flags = lhs.flags | rhs.flags;
  result.xfrm = lhs.xfrm | rhs.xfrm;

  return result;
}

SecsAttributeSet &operator|=(SecsAttributeSet &lhs,
                             const SecsAttributeSet &rhs) {
  lhs.flags |= rhs.flags;
  lhs.xfrm |= rhs.xfrm;

  return lhs;
}

SecsAttributeSet operator&(const SecsAttributeSet &lhs,
                           const SecsAttributeSet &rhs) {
  SecsAttributeSet result;
  result.flags = lhs.flags & rhs.flags;
  result.xfrm = lhs.xfrm & rhs.xfrm;

  return result;
}

SecsAttributeSet &operator&=(SecsAttributeSet &lhs,
                             const SecsAttributeSet &rhs) {
  lhs.flags &= rhs.flags;
  lhs.xfrm &= rhs.xfrm;

  return lhs;
}

SecsAttributeSet operator^(const SecsAttributeSet &lhs,
                           const SecsAttributeSet &rhs) {
  SecsAttributeSet result;
  result.flags = lhs.flags ^ rhs.flags;
  result.xfrm = lhs.xfrm ^ rhs.xfrm;

  return result;
}

SecsAttributeSet &operator^=(SecsAttributeSet &lhs,
                             const SecsAttributeSet &rhs) {
  lhs.flags ^= rhs.flags;
  lhs.xfrm ^= rhs.xfrm;

  return lhs;
}

SecsAttributeSet operator~(const SecsAttributeSet &value) {
  SecsAttributeSet tmp;
  tmp.flags = ~value.flags;
  tmp.xfrm = ~value.xfrm;
  return tmp;
}

bool operator==(const SecsAttributeSet &lhs, const SecsAttributeSet &rhs) {
  return memcmp(&lhs, &rhs, sizeof(lhs)) == 0;
}

bool operator!=(const SecsAttributeSet &lhs, const SecsAttributeSet &rhs) {
  return !(lhs == rhs);
}

}  // namespace sgx
}  // namespace asylo
