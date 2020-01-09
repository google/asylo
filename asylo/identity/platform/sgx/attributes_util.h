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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_ATTRIBUTES_UTIL_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_ATTRIBUTES_UTIL_H_

#include <vector>

#include "absl/strings/string_view.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

/// @file attributes_util.h
/// @brief This library implements operations and utility functions on
/// Attributes messages.

namespace asylo {
namespace sgx {

/// Computes the bitwise AND of two Attributes protos.
Attributes operator&(const Attributes &lhs, const Attributes &rhs);

/// Checks two Attributes protos for equality.
bool operator==(const Attributes &lhs, const Attributes &rhs);

/// Checks two Attributes protos for inequality.
bool operator!=(const Attributes &lhs, const Attributes &rhs);

/// Sets the given `bit` of `attributes` to true, or returns a non-OK Status if
/// the `bit` was invalid.
Status SetAttributeBit(AttributeBit bit, Attributes *attributes);

/// Sets the given `bit` of `attributes` to false, or returns a non-OK Status if
/// the `bit` was invalid.
Status ClearAttributeBit(AttributeBit bit, Attributes *attributes);

/// Returns whether the given `bit` of `attributes` is set, or a non-OK Status
/// if the `bit` was invalid.
StatusOr<bool> IsAttributeBitSet(AttributeBit bit,
                                 const Attributes &attributes);

/// Returns a printable list of the bits set in `attributes`.
std::vector<absl::string_view> GetPrintableAttributeList(
    const Attributes &attributes);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_ATTRIBUTES_UTIL_H_
