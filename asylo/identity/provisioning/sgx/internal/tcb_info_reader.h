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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_TCB_INFO_READER_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_TCB_INFO_READER_H_

#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/hash/hash.h"
#include "asylo/identity/provisioning/sgx/internal/container_util.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/identity/sgx/pck_certificates.pb.h"

namespace asylo {
namespace sgx {

// An enum representing the different possible relationships between a valid PCK
// certificate set and a valid TCB info.
enum class ProvisioningConsistency {
  // The PCK certificate set and TCB info are consistent with each other. In
  // other words, every TCB level in the TCB info is represented in the PCK
  // certificates and every TCB level represented in the PCK certificates is in
  // the TCB info.
  kConsistent,

  // A fresher TCB info is available. In other words, there are TCB levels
  // represented in the PCK certificates that are not in the TCB info.
  kTcbInfoStale,

  // A fresher PCK certificate set is available. In other words, there are TCB
  // levels in the TCB info that are not represented in the PCK certificates.
  kPckCertificatesStale,

  // Both the PCK certificate set and the TCB info have TCB levels that are not
  // in the other. This should never happen with real data from Intel.
  kOtherInconsistency,
};

// A class that provides provisioning information based on TCB info.
class TcbInfoReader {
 public:
  // Constructs a new TcbInfoReader based on |tcb_info|, which must be valid
  // according to ValidateTcbInfo().
  explicit TcbInfoReader(const TcbInfo &tcb_info);

  // Returns the consistency relationship between the contained TCB info and
  // |pck_certificates|. See the comments on ProvisioningConsistency for more
  // information on the different possible return values.
  //
  // The |pck_certificates| must be valid according to
  // ValidatePckCertificates(). If they are not, then the output will not be
  // accurate.
  ProvisioningConsistency GetConsistencyWith(
      const PckCertificates &pck_certificates) const;

 private:
  // The TCB levels from the TCB info.
  absl::flat_hash_set<Tcb, absl::Hash<Tcb>, MessageEqual> tcb_levels_;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_TCB_INFO_READER_H_
