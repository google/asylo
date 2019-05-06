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

#include "asylo/util/status.h"

namespace asylo {
namespace sgx {
namespace {

// All bits in the MISCSELECT bit vector.
constexpr SecsMiscselectBit kAllSecsMiscselectBits[] = {
    SecsMiscselectBit::EXINFO};

std::string GetMiscselectBitName(SecsMiscselectBit miscselect_bit) {
  switch (miscselect_bit) {
    case SecsMiscselectBit::EXINFO:
      return "EXINFO";
    default:
      return "UNKNOWN";
  }
}

}  // namespace

StatusOr<bool> TestMiscselectBit(SecsMiscselectBit miscselect_bit,
                                 uint32_t miscselect) {
  size_t bit_position = static_cast<size_t>(miscselect_bit);
  if (bit_position >= 32) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Invalid bit position for MISCSELECT bit vector: "
                  "(max allowed value is 31)");
  }

  return (miscselect & (UINT32_C(1) << bit_position)) != 0;
}

StatusOr<bool> TestMiscselectBit(SecsMiscselectBit miscselect_bit,
                                 const Miscselect &miscselect) {
  return TestMiscselectBit(miscselect_bit, miscselect.value());
}

std::vector<std::string> GetPrintableMiscselectList(uint32_t miscselect) {
  std::vector<std::string> printable_miscselect_list;
  for (SecsMiscselectBit miscselect_bit : kAllSecsMiscselectBits) {
    size_t bit_position = static_cast<size_t>(miscselect_bit);
    if ((miscselect & (UINT32_C(1) << bit_position)) != 0) {
      printable_miscselect_list.emplace_back(
          GetMiscselectBitName(miscselect_bit));
    }
  }
  return printable_miscselect_list;
}

std::vector<std::string> GetPrintableMiscselectList(
    const Miscselect &miscselect) {
  return GetPrintableMiscselectList(miscselect.value());
}

}  // namespace sgx
}  // namespace asylo
