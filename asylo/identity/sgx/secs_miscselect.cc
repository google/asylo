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

#include "asylo/identity/sgx/secs_miscselect.h"

#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {


absl::string_view GetMiscselectBitName(MiscselectBit miscselect_bit) {
  static constexpr absl::string_view kExinfo = "EXINFO";
  static constexpr absl::string_view kUnknown = "UNKNOWN";
  switch (miscselect_bit) {
    case MiscselectBit::EXINFO:
      return kExinfo;
    default:
      return kUnknown;
  }
}

}  // namespace

StatusOr<bool> TestMiscselectBit(MiscselectBit miscselect_bit,
                                 uint32_t miscselect) {
  size_t bit_position = static_cast<size_t>(miscselect_bit);
  if (bit_position >= 32) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Invalid bit position for MISCSELECT bit vector: "
                  "(max allowed value is 31)");
  }

  return (miscselect & (UINT32_C(1) << bit_position)) != 0;
}

StatusOr<bool> TestMiscselectBit(MiscselectBit miscselect_bit,
                                 const Miscselect &miscselect) {
  return TestMiscselectBit(miscselect_bit, miscselect.value());
}

std::vector<absl::string_view> GetPrintableMiscselectList(uint32_t miscselect) {
  std::vector<absl::string_view> printable_miscselect_list;
  for (MiscselectBit miscselect_bit : kAllMiscselectBits) {
    size_t bit_position = static_cast<size_t>(miscselect_bit);
    if ((miscselect & (UINT32_C(1) << bit_position)) != 0) {
      printable_miscselect_list.push_back(
          GetMiscselectBitName(miscselect_bit));
    }
  }
  return printable_miscselect_list;
}

std::vector<absl::string_view> GetPrintableMiscselectList(
    const Miscselect &miscselect) {
  return GetPrintableMiscselectList(miscselect.value());
}

}  // namespace sgx
}  // namespace asylo
