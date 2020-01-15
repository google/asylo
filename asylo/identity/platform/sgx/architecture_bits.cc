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

#include "asylo/identity/platform/sgx/architecture_bits.h"

#include <bitset>
#include <cstddef>
#include <cstdint>

namespace asylo {
namespace sgx {
namespace {

// Returns a bitmask corresponding to the bits specified in kAllAttributeBits,
// from bits |offset| to |offset| + 63. This corresponds to to the flag bits
// when offset == 0, and the XFRM bits when offset == 64.
uint64_t GetValidAttributeBitmask(size_t offset) {
  std::bitset<64> mask;

  for (AttributeBit bit : kAllAttributeBits) {
    size_t bit_position = static_cast<size_t>(bit);
    if (bit_position >= offset && bit_position < offset + mask.size()) {
      mask.set(bit_position - offset);
    }
  }

  return mask.to_ullong();
}

// Returns a bitmask corresponding to the bits specified in kAllMiscselectBits.
uint32_t GetValidMiscselectBitmask() {
  std::bitset<32> mask;

  for (MiscselectBit bit : kAllMiscselectBits) {
    size_t bit_position = static_cast<size_t>(bit);
    mask.set(bit_position);
  }

  return mask.to_ulong();
}

}  // namespace

const AttributeBit kAllAttributeBits[15] = {
    AttributeBit::INIT,         AttributeBit::DEBUG,
    AttributeBit::MODE64BIT,    AttributeBit::PROVISIONKEY,
    AttributeBit::INITTOKENKEY, AttributeBit::KSS,
    AttributeBit::FPU,          AttributeBit::SSE,
    AttributeBit::AVX,          AttributeBit::BNDREG,
    AttributeBit::BNDCSR,       AttributeBit::OPMASK,
    AttributeBit::ZMM_HI256,    AttributeBit::HI16_ZMM,
    AttributeBit::PKRU};

const size_t kNumAttributeFlagBits = 64;

const size_t kNumAttributeXfrmBits = 64;

const size_t kNumAttributeBits = kNumAttributeFlagBits + kNumAttributeXfrmBits;

const uint64_t kValidAttributeFlagsBitmask = GetValidAttributeBitmask(0);

const uint64_t kValidAttributeXfrmBitmask =
    GetValidAttributeBitmask(kNumAttributeFlagBits);

const MiscselectBit kAllMiscselectBits[1] = {MiscselectBit::EXINFO};

const size_t kNumMiscselectBits = 32;

const uint32_t kValidMiscselectBitmask = GetValidMiscselectBitmask();

}  // namespace sgx
}  // namespace asylo
