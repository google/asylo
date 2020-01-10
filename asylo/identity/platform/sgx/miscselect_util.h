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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_MISCSELECT_UTIL_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_MISCSELECT_UTIL_H_

#include <vector>

#include "absl/strings/string_view.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/miscselect.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

/// @file miscselect_util.h
/// @brief This library implements operations and utility functions on the proto
/// and uint32 representations of the MISCSELECT structure.

namespace asylo {
namespace sgx {

/// Checks two Miscselect protos for equality.
bool operator==(const Miscselect &lhs, const Miscselect &rhs);

/// Checks two Miscselect protos for inequality.
bool operator!=(const Miscselect &lhs, const Miscselect &rhs);

/// Sets the given `bit` of `miscselect` to true, or returns a non-OK Status if
/// the `bit` was invalid.
Status SetMiscselectBit(MiscselectBit bit, uint32_t *miscselect);
Status SetMiscselectBit(MiscselectBit bit, Miscselect *miscselect);

/// Sets the given `bit` of `miscselect` to false, or returns a non-OK Status if
/// the `bit` was invalid.
Status ClearMiscselectBit(MiscselectBit bit, uint32_t *miscselect);
Status ClearMiscselectBit(MiscselectBit bit, Miscselect *miscselect);

/// Returns whether the given `bit` of `miscselect` is set, or returns a non-OK
/// Status if the `bit` was invalid.
StatusOr<bool> IsMiscselectBitSet(MiscselectBit bit, uint32_t miscselect);
StatusOr<bool> IsMiscselectBitSet(MiscselectBit bit,
                                  const Miscselect &miscselect);

/// Returns a printable list of the bits set in `miscselect`.
std::vector<absl::string_view> GetPrintableMiscselectList(uint32_t miscselect);
std::vector<absl::string_view> GetPrintableMiscselectList(
    const Miscselect &miscselect);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_MISCSELECT_UTIL_H_
