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

#include "asylo/identity/platform/sgx/attributes_util.h"

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

constexpr size_t kNumFlagsBits = 64;
constexpr size_t kNumXfrmBits = 64;
constexpr size_t kNumAttributeBits = kNumFlagsBits + kNumXfrmBits;

absl::string_view GetAttributeName(AttributeBit attribute) {
  switch (attribute) {
    case AttributeBit::INIT:
      return "INIT";
    case AttributeBit::DEBUG:
      return "DEBUG";
    case AttributeBit::MODE64BIT:
      return "MODE64BIT";
    case AttributeBit::PROVISIONKEY:
      return "PROVISIONKEY";
    case AttributeBit::INITTOKENKEY:
      return "INITTOKENKEY";
    case AttributeBit::KSS:
      return "KSS";
    case AttributeBit::FPU:
      return "FPU";
    case AttributeBit::SSE:
      return "SSE";
    case AttributeBit::AVX:
      return "AVX";
    case AttributeBit::BNDREG:
      return "BNDREG";
    case AttributeBit::BNDCSR:
      return "BNDCSR";
    case AttributeBit::OPMASK:
      return "OPMASK";
    case AttributeBit::ZMM_HI256:
      return "ZMM_HI256";
    case AttributeBit::HI16_ZMM:
      return "HI16_ZMM";
    case AttributeBit::PKRU:
      return "PKRU";
  }

  return "UNKNOWN";
}

StatusOr<uint64_t> GetAttributeBitMask(size_t bit_position) {
  if (bit_position >= kNumAttributeBits) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("AttributeBit specifies an invalid bit position: ",
                     bit_position));
  }

  return 1ULL << (bit_position % kNumFlagsBits);
}

}  // namespace

Attributes operator&(const Attributes &lhs, const Attributes &rhs) {
  Attributes result;
  result.set_flags(lhs.flags() & rhs.flags());
  result.set_xfrm(lhs.xfrm() & rhs.xfrm());
  return result;
}

bool operator==(const Attributes &lhs, const Attributes &rhs) {
  return lhs.flags() == rhs.flags() && lhs.xfrm() == rhs.xfrm();
}

bool operator!=(const Attributes &lhs, const Attributes &rhs) {
  return !(lhs == rhs);
}

Status SetAttributeBit(AttributeBit bit, Attributes *attributes) {
  size_t bit_position = static_cast<size_t>(bit);

  uint64_t mask;
  ASYLO_ASSIGN_OR_RETURN(mask, GetAttributeBitMask(bit_position));

  if (bit_position < kNumFlagsBits) {
    attributes->set_flags(attributes->flags() | mask);
  } else {
    attributes->set_xfrm(attributes->xfrm() | mask);
  }
  return absl::OkStatus();
}

Status ClearAttributeBit(AttributeBit bit, Attributes *attributes) {
  size_t bit_position = static_cast<size_t>(bit);

  uint64_t mask;
  ASYLO_ASSIGN_OR_RETURN(mask, GetAttributeBitMask(bit_position));

  if (bit_position < kNumFlagsBits) {
    attributes->set_flags(attributes->flags() & ~mask);
  } else {
    attributes->set_xfrm(attributes->xfrm() & ~mask);
  }
  return absl::OkStatus();
}

StatusOr<bool> IsAttributeBitSet(AttributeBit bit,
                                 const Attributes &attributes) {
  size_t bit_position = static_cast<size_t>(bit);

  uint64_t mask;
  ASYLO_ASSIGN_OR_RETURN(mask, GetAttributeBitMask(bit_position));

  if (bit_position < kNumFlagsBits) {
    return attributes.flags() & mask;
  } else {
    return attributes.xfrm() & mask;
  }
}

std::vector<absl::string_view> GetPrintableAttributeList(
    const Attributes &attributes) {
  std::vector<absl::string_view> printable_list;
  for (AttributeBit bit : kAllAttributeBits) {
    StatusOr<bool> set_status = IsAttributeBitSet(bit, attributes);
    if (set_status.ok() && set_status.value()) {
      printable_list.push_back(GetAttributeName(bit));
    }
  }
  return printable_list;
}

}  // namespace sgx
}  // namespace asylo
