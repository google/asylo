/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/identity/platform/sgx/miscselect_util.h"

#include <cstdint>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/miscselect.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

constexpr size_t kNumMiscselectBits = 32;

absl::string_view GetMiscselectBitName(MiscselectBit miscselect_bit) {
  switch (miscselect_bit) {
    case MiscselectBit::EXINFO:
      return "EXINFO";
  }
  return "UNKNOWN";
}

StatusOr<size_t> GetMiscselectBitMask(size_t bit_position) {
  if (bit_position >= kNumMiscselectBits) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("MiscselectBit specifies an invalid bit position: ",
                     bit_position));
  }

  return 1 << bit_position;
}

}  // namespace

bool operator==(const Miscselect &lhs, const Miscselect &rhs) {
  return lhs.value() == rhs.value();
}

bool operator!=(const Miscselect &lhs, const Miscselect &rhs) {
  return !(lhs == rhs);
}

Status SetMiscselectBit(MiscselectBit bit, uint32_t *miscselect) {
  size_t bit_position = static_cast<size_t>(bit);

  size_t mask;
  ASYLO_ASSIGN_OR_RETURN(mask, GetMiscselectBitMask(bit_position));

  *miscselect |= mask;
  return absl::OkStatus();
}

Status SetMiscselectBit(MiscselectBit bit, Miscselect *miscselect) {
  uint32_t miscselect_value = miscselect->value();
  ASYLO_RETURN_IF_ERROR(SetMiscselectBit(bit, &miscselect_value));
  miscselect->set_value(miscselect_value);
  return absl::OkStatus();
}

Status ClearMiscselectBit(MiscselectBit bit, uint32_t *miscselect) {
  size_t bit_position = static_cast<size_t>(bit);

  size_t mask;
  ASYLO_ASSIGN_OR_RETURN(mask, GetMiscselectBitMask(bit_position));

  *miscselect &= ~mask;
  return absl::OkStatus();
}

Status ClearMiscselectBit(MiscselectBit bit, Miscselect *miscselect) {
  uint32_t miscselect_value = miscselect->value();
  ASYLO_RETURN_IF_ERROR(ClearMiscselectBit(bit, &miscselect_value));
  miscselect->set_value(miscselect_value);
  return absl::OkStatus();
}

StatusOr<bool> IsMiscselectBitSet(MiscselectBit bit, uint32_t miscselect) {
  size_t bit_position = static_cast<size_t>(bit);

  size_t mask;
  ASYLO_ASSIGN_OR_RETURN(mask, GetMiscselectBitMask(bit_position));

  return miscselect & mask;
}

StatusOr<bool> IsMiscselectBitSet(MiscselectBit bit,
                                  const Miscselect &miscselect) {
  return IsMiscselectBitSet(bit, miscselect.value());
}

std::vector<absl::string_view> GetPrintableMiscselectList(uint32_t miscselect) {
  std::vector<absl::string_view> printable_list;
  for (MiscselectBit bit : kAllMiscselectBits) {
    StatusOr<bool> set_status = IsMiscselectBitSet(bit, miscselect);
    if (set_status.ok() && set_status.value()) {
      printable_list.push_back(GetMiscselectBitName(bit));
    }
  }
  return printable_list;
}

std::vector<absl::string_view> GetPrintableMiscselectList(
    const Miscselect &miscselect) {
  return GetPrintableMiscselectList(miscselect.value());
}

}  // namespace sgx
}  // namespace asylo
