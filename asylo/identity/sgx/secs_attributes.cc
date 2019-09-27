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

#include "asylo/identity/sgx/secs_attributes.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "asylo/util/logging.h"
#include "asylo/identity/sgx/attributes.pb.h"

namespace asylo {
namespace sgx {
namespace {

constexpr size_t kByteBits = 8;
constexpr size_t kNumFlagsBits =
    sizeof(static_cast<SecsAttributeSet *>(nullptr)->flags) * kByteBits;
constexpr size_t kNumXfrmBits =
    sizeof(static_cast<SecsAttributeSet *>(nullptr)->xfrm) * kByteBits;
constexpr size_t kNumSecsAttributeBits = kNumFlagsBits + kNumXfrmBits;

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
constexpr SecsAttributeBit kDefaultDoNotCareSecsAttributes[] = {
    SecsAttributeBit::FPU,       SecsAttributeBit::SSE,
    SecsAttributeBit::AVX,       SecsAttributeBit::OPMASK,
    SecsAttributeBit::ZMM_HI256, SecsAttributeBit::HI16_ZMM};

// All attribute bits.
constexpr SecsAttributeBit kAllSecsAttributes[] = {
    SecsAttributeBit::INIT,         SecsAttributeBit::DEBUG,
    SecsAttributeBit::MODE64BIT,    SecsAttributeBit::PROVISIONKEY,
    SecsAttributeBit::INITTOKENKEY, SecsAttributeBit::KSS,
    SecsAttributeBit::FPU,          SecsAttributeBit::SSE,
    SecsAttributeBit::AVX,          SecsAttributeBit::BNDREG,
    SecsAttributeBit::BNDCSR,       SecsAttributeBit::OPMASK,
    SecsAttributeBit::ZMM_HI256,    SecsAttributeBit::HI16_ZMM,
    SecsAttributeBit::PKRU};

// Must-be-one attribute bits
constexpr SecsAttributeBit kMustBeSetAttributes[] = {
    SecsAttributeBit::INIT, SecsAttributeBit::FPU, SecsAttributeBit::SSE};

std::pair<SecsAttributeBit, const char *> kPrintableSecsAttributeBitNames[] = {
    {SecsAttributeBit::INIT, "INIT"},
    {SecsAttributeBit::DEBUG, "DEBUG"},
    {SecsAttributeBit::MODE64BIT, "MODE64BIT"},
    // Bit 3 is an unused bit.
    {SecsAttributeBit::PROVISIONKEY, "PROVISIONKEY"},
    {SecsAttributeBit::INITTOKENKEY, "INITTOKENKEY"},
    // Bit 6 is an unused bit.
    {SecsAttributeBit::KSS, "KSS"},
    // Bits 8 through 63 are unused.
    {SecsAttributeBit::FPU, "FPU"},
    {SecsAttributeBit::SSE, "SSE"},
    {SecsAttributeBit::AVX, "AVX"},
    {SecsAttributeBit::BNDREG, "BNDREG"},
    {SecsAttributeBit::BNDCSR, "BNDCSR"},
    {SecsAttributeBit::OPMASK, "OPMASK"},
    {SecsAttributeBit::ZMM_HI256, "ZMM_HI256"},
    {SecsAttributeBit::HI16_ZMM, "HI16_ZMM"},
    {SecsAttributeBit::PKRU, "PKRU"}};

absl::string_view GetAttributeName(SecsAttributeBit attribute) {
  static constexpr absl::string_view kUnknown = "UNKNOWN";
  for (const std::pair<SecsAttributeBit, const char *> &attribute_name_pair :
       kPrintableSecsAttributeBitNames) {
    if (attribute_name_pair.first == attribute) {
      return attribute_name_pair.second;
    }
  }
  return kUnknown;
}

}  // namespace

StatusOr<SecsAttributeSet> MakeSecsAttributeSet(
    const std::vector<SecsAttributeBit> &attribute_list) {
  SecsAttributeSet attribute_set;
  if (!ConvertSecsAttributeRepresentation(attribute_list, &attribute_set)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Input attribute list contains invalid attribute bits");
  }
  return attribute_set;
}

void ClearSecsAttributeSet(SecsAttributeSet *attributes) {
  attributes->flags = 0;
  attributes->xfrm = 0;
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

bool ConvertSecsAttributeRepresentation(
    const std::vector<SecsAttributeBit> &attribute_list,
    SecsAttributeSet *attributes) {
  ClearSecsAttributeSet(attributes);
  for (SecsAttributeBit attribute : attribute_list) {
    size_t bit_position = static_cast<size_t>(attribute);
    if (bit_position >= kNumSecsAttributeBits) {
      LOG(ERROR) << "SecsAttributeBit specifies a bit position " << bit_position
                 << " that is larger than the max allowed value of "
                 << kNumSecsAttributeBits - 1;
      return false;
    }
    if (bit_position < kNumFlagsBits) {
      attributes->flags |= (1ULL << bit_position);
    } else {
      attributes->xfrm |= (1ULL << (bit_position - kNumFlagsBits));
    }
  }
  return true;
}

bool ConvertSecsAttributeRepresentation(
    const SecsAttributeSet &attributes,
    std::vector<SecsAttributeBit> *attribute_list) {
  attribute_list->clear();
  for (uint32_t i = 0; i < kNumFlagsBits; i++) {
    if (attributes.flags & (1ULL << i)) {
      attribute_list->push_back(static_cast<SecsAttributeBit>(i));
    }
  }
  for (uint32_t i = 0; i < kNumXfrmBits; i++) {
    if (attributes.xfrm & (1ULL << i)) {
      attribute_list->push_back(
          static_cast<SecsAttributeBit>(i + kNumFlagsBits));
    }
  }
  return true;
}

bool ConvertSecsAttributeRepresentation(
    const std::vector<SecsAttributeBit> &attribute_list,
    Attributes *attributes) {
  attributes->Clear();
  for (SecsAttributeBit attribute : attribute_list) {
    size_t bit_position = static_cast<size_t>(attribute);
    if (bit_position >= kNumSecsAttributeBits) {
      LOG(ERROR) << "SecsAttributeBit specifies a bit position " << bit_position
                 << " that is larger than the max allowed value of "
                 << kNumSecsAttributeBits - 1;
      return false;
    }
    if (bit_position < kNumFlagsBits) {
      attributes->set_flags(attributes->flags() | (1ULL << bit_position));
    } else {
      attributes->set_xfrm(attributes->xfrm() |
                           (1ULL << (bit_position - kNumFlagsBits)));
    }
  }
  return true;
}

bool ConvertSecsAttributeRepresentation(
    const Attributes &attributes,
    std::vector<SecsAttributeBit> *attribute_list) {
  attribute_list->clear();
  for (uint32_t i = 0; i < kNumFlagsBits; i++) {
    if (attributes.flags() & (1ULL << i)) {
      attribute_list->push_back(static_cast<SecsAttributeBit>(i));
    }
  }
  for (uint32_t i = 0; i < kNumXfrmBits; i++) {
    if (attributes.xfrm() & (1ULL << i)) {
      attribute_list->push_back(
          static_cast<SecsAttributeBit>(i + kNumFlagsBits));
    }
  }
  return true;
}

bool ConvertSecsAttributeRepresentation(const SecsAttributeSet &attributes_set,
                                        Attributes *attributes) {
  attributes->set_flags(attributes_set.flags);
  attributes->set_xfrm(attributes_set.xfrm);
  return true;
}

bool ConvertSecsAttributeRepresentation(const Attributes &attributes,
                                        SecsAttributeSet *attributes_set) {
  attributes_set->flags = attributes.flags();
  attributes_set->xfrm = attributes.xfrm();
  return true;
}

bool TestAttribute(SecsAttributeBit attribute,
                   const SecsAttributeSet &attributes_set) {
  size_t bit_position = static_cast<size_t>(attribute);
  if (bit_position >= kNumSecsAttributeBits) {
    LOG(INFO) << "SecsAttributeBit specifies a bit position " << bit_position
              << " that is larger than the max allowed value of "
              << kNumSecsAttributeBits - 1;
    return false;
  }

  if (bit_position < kNumFlagsBits) {
    return (attributes_set.flags & (1ULL << bit_position)) != 0;
  } else {
    return (attributes_set.xfrm & (1ULL << (bit_position - kNumFlagsBits))) !=
           0;
  }
}

bool TestAttribute(SecsAttributeBit attribute, const Attributes &attributes) {
  size_t bit_position = static_cast<size_t>(attribute);
  if (bit_position >= kNumSecsAttributeBits) {
    LOG(INFO) << "SecsAttributeBit specifies a bit position " << bit_position
              << " that is larger than the max allowed value of "
              << kNumSecsAttributeBits - 1;
    return false;
  }

  if (bit_position < kNumFlagsBits) {
    return (attributes.flags() & (1ULL << bit_position)) != 0;
  } else {
    return (attributes.xfrm() & (1ULL << (bit_position - kNumFlagsBits))) != 0;
  }
}

bool GetAllSecsAttributes(SecsAttributeSet *attributes) {
  std::vector<SecsAttributeBit> attribute_list(
      kAllSecsAttributes,
      kAllSecsAttributes + ABSL_ARRAYSIZE(kAllSecsAttributes));
  return ConvertSecsAttributeRepresentation(attribute_list, attributes);
}

bool GetAllSecsAttributes(Attributes *attributes) {
  std::vector<SecsAttributeBit> attribute_list(
      kAllSecsAttributes,
      kAllSecsAttributes + ABSL_ARRAYSIZE(kAllSecsAttributes));
  return ConvertSecsAttributeRepresentation(attribute_list, attributes);
}

bool GetMustBeSetSecsAttributes(SecsAttributeSet *attributes) {
  std::vector<SecsAttributeBit> attribute_list(
      kMustBeSetAttributes,
      kMustBeSetAttributes + ABSL_ARRAYSIZE(kMustBeSetAttributes));
  return ConvertSecsAttributeRepresentation(attribute_list, attributes);
}

bool GetMustBeSetSecsAttributes(Attributes *attributes) {
  std::vector<SecsAttributeBit> attribute_list(
      kMustBeSetAttributes,
      kMustBeSetAttributes + ABSL_ARRAYSIZE(kMustBeSetAttributes));
  return ConvertSecsAttributeRepresentation(attribute_list, attributes);
}

bool GetDefaultDoNotCareSecsAttributes(
    std::vector<SecsAttributeBit> *attribute_list) {
  *attribute_list = std::vector<SecsAttributeBit>(
      kDefaultDoNotCareSecsAttributes,
      kDefaultDoNotCareSecsAttributes +
          ABSL_ARRAYSIZE(kDefaultDoNotCareSecsAttributes));
  return true;
}

bool GetDefaultDoNotCareSecsAttributes(SecsAttributeSet *attributes) {
  std::vector<SecsAttributeBit> attribute_list(
      kDefaultDoNotCareSecsAttributes,
      kDefaultDoNotCareSecsAttributes +
          ABSL_ARRAYSIZE(kDefaultDoNotCareSecsAttributes));
  return ConvertSecsAttributeRepresentation(attribute_list, attributes);
}

bool GetDefaultDoNotCareSecsAttributes(Attributes *attributes) {
  std::vector<SecsAttributeBit> attribute_list(
      kDefaultDoNotCareSecsAttributes,
      kDefaultDoNotCareSecsAttributes +
          ABSL_ARRAYSIZE(kDefaultDoNotCareSecsAttributes));
  return ConvertSecsAttributeRepresentation(attribute_list, attributes);
}

Status SetDefaultSecsAttributesMask(Attributes *attributes_match_mask) {
  SecsAttributeSet attributes;
  if (!GetDefaultDoNotCareSecsAttributes(&attributes)) {
    return Status(error::GoogleError::INTERNAL,
                  "Could not determine default \"DO NOT CARE\" attributes");
  }
  // The default attributes_match_mask is a logical NOT of the default "DO NOT
  // CARE" attributes.
  if (!ConvertSecsAttributeRepresentation(~attributes, attributes_match_mask)) {
    return Status(
        error::GoogleError::INTERNAL,
        "Could not convert hardware SecsAttributeSet to Attributes");
  }

  return Status::OkStatus();
}

void SetStrictSecsAttributesMask(Attributes *attributes_match_mask) {
  attributes_match_mask->set_flags(std::numeric_limits<uint64_t>::max());
  attributes_match_mask->set_xfrm(std::numeric_limits<uint64_t>::max());
}

void GetPrintableAttributeList(
    const std::vector<SecsAttributeBit> &attribute_list,
    std::vector<absl::string_view> *printable_list) {
  printable_list->clear();
  for (SecsAttributeBit attribute : attribute_list) {
    printable_list->push_back(GetAttributeName(attribute));
  }
}

void GetPrintableAttributeList(const SecsAttributeSet &attributes,
                               std::vector<absl::string_view> *printable_list) {
  std::vector<SecsAttributeBit> attribute_list;
  ConvertSecsAttributeRepresentation(attributes, &attribute_list);
  GetPrintableAttributeList(attribute_list, printable_list);
}

void GetPrintableAttributeList(const Attributes &attributes,
                               std::vector<absl::string_view> *printable_list) {
  std::vector<SecsAttributeBit> attribute_list;
  ConvertSecsAttributeRepresentation(attributes, &attribute_list);
  GetPrintableAttributeList(attribute_list, printable_list);
}

}  // namespace sgx
}  // namespace asylo
