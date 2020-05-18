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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_TCB_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_TCB_H_

#include <cstddef>

#include "absl/base/attributes.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// Size of Provisioning Certification Enclave Security Version Number (PCE SVN).
ABSL_CONST_INIT extern const size_t kPcesvnSize;

// Size of the serialized RawTcb.
ABSL_CONST_INIT extern const size_t kRawTcbSize;

// The possible orders between two objects in a partial ordering.
//
// A partial ordering is an ordering in which one object may be less than, equal
// to, or greater than another, or also entirely incomparable to it. For
// instance, a class hierarchy is partially ordered by the subclass relation.
//
// For more information about partial orderings, see:
// https://en.wikipedia.org/wiki/Partially_ordered_set.
enum class PartialOrder {
  kLess,
  kEqual,
  kGreater,
  kIncomparable,
};

// Size of the |components| field of a Tcb message. This value is fixed at 16.
constexpr int kTcbComponentsSize = 16;

// Validates a Tcb message. Returns an OK status if and only if the message is
// valid.
//
// A Tcb message is valid if and only if its |components| and |pce_svn| fields
// are set, |components| has exactly kTcbComponentsSize bytes, and |pce_svn| is
// valid according to ValidatePceSvn().
Status ValidateTcb(const Tcb &tcb);

// Validates a RawTcb message. Returns an OK status if and only if the message
// is valid.
//
// A RawTcb message is valid if and only if its |cpu_svn| and |pce_svn| fields
// are set and both are valid according to their respective types' validators.
Status ValidateRawTcb(const RawTcb &raw_tcb);

// Validates a TcbInfo message. Returns an OK status if and only if the message
// is valid.
//
// A TcbInfo message is valid if it contains an |impl| variant which is valid.
// The |impl| is valid if and only if:
//
//   * Its |version|, |issue_date|, |next_update|, |fmspc|, and |pce_id| fields
//     are set.
//   * Each of those fields is valid according its type's validator.
//   * Each element of |tcb_levels| is valid under the |version| (see below).
//   * The |version| is a known value (currently 1 or 2).
//   * The |issue_date| is before the |next_update|.
//   * Any contained TcbLevels with the same |tcb| also have the same |status|.
//   * The |tcb_type| and |tcb_evaluation_data_number| fields are set if and
//     only if the |version| is 2, in which case the |tcb_type| must be valid.
//
// Each TcbLevel is valid if and only if:
//
//   * Its |tcb| and |status| fields are both set.
//   * The |tcb_date| field is set if and only if the TcbInfo's |version| is 2.
//   * If the TcbInfo's |version| is 1, then the |advisory_ids| field is empty.
//   * The |tcb| field is valid according to ValidateTcb().
//   * Either the |status| is a |known_status| that is not INVALID or it is an
//     |unknown_status|.
//
// A |status| is NOT considered invalid if it has an |unknown_status| string
// that represents an existing StatusType value. This allows new cases to be
// added to TcbStatus.StatusType without invalidating old data.
Status ValidateTcbInfo(const TcbInfo &tcb_info);

// Returns the order between |lhs| and |rhs|. Both |lhs| and |rhs| must be valid
// Tcb objects. Returns an error if |tcb_type| is not a recognized Intel TCB
// type, as found in the TCB info structure.
//
// The algorithm used to determine the ordering of TCBs is inferred from the
// instructions at
// https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v2
// and depends on |tcb_type|.
//
// For a |tcb_type| of 0, |lhs| is less than or equal to |rhs| if both:
//
//   * For each i in the range [0, kTcbComponentsSize), the following is true:
//
//         lhs.components(i) <= rhs.components(i)
//
//   * Also:
//
//         lhs.pce_svn().value() <= rhs.pce_svn().value()
//
// As usual in a partial order, |lhs| is greater than or equal to |rhs| if |rhs|
// is less than or equal to |lhs|. In either of those cases, if |lhs| is not
// actually equal to |rhs|, then it is strictly less or greater. If |lhs| is
// neither less than or equal to nor greater than or equal to |rhs|, then |lhs|
// and |rhs| are incomparable.
StatusOr<PartialOrder> CompareTcbs(TcbType tcb_type, const Tcb &lhs,
                                   const Tcb &rhs);

// Parses a hex-encoded string |raw_tcb_hex| into the RawTcb protobuf.
// |raw_tcb_hex| can come from the "SGB-TCBm" JSON field in the response of
// Intel PCS's GetPckCertificate API
// (https://api.portal.trustedservices.intel.com/documentation#pcs-certificate-v2).
// Returns a non-OK Status if |raw_tcb_hex| is not a hex string encoding an
// 18-byte raw TCB.
StatusOr<RawTcb> ParseRawTcbHex(absl::string_view raw_tcb_hex);

// Converts a TcbStatus to a TCB level status string. Succeeds if and only if
// |status| either has an |unknown_status| value or is one of UP_TO_DATE,
// CONFIGURATION_NEEDED, OUT_OF_DATE, or REVOKED.
StatusOr<std::string> TcbStatusToString(const TcbStatus &status);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_TCB_H_
