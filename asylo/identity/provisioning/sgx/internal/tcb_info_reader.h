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
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/container_util.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certificates.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/util/statusor.h"

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
  TcbInfoReader() = default;

  // Creates a new TcbInfoReader based on |tcb_info|. Returns an error if
  // |tcb_info| is not valid according to ValidateTcbInfo().
  static StatusOr<TcbInfoReader> Create(TcbInfo tcb_info);

  // Returns the TCB info that this TcbInfoReader represents.
  const TcbInfo &GetTcbInfo() const;

  // Returns the Configuration ID corresponding to |cpu_svn| under the
  // configured TCB info.
  StatusOr<ConfigurationId> GetConfigurationId(const CpuSvn &cpu_svn) const;

  // Returns the consistency relationship between the contained TCB info and
  // |pck_certificates|. See the comments on ProvisioningConsistency for more
  // information on the different possible return values.
  //
  // Returns an error if |pck_ceritifactes| is not valid according to
  // ValidatePckCertificates().
  StatusOr<ProvisioningConsistency> GetConsistencyWith(
      const PckCertificates &pck_certificates) const;

 private:
  TcbInfoReader(
      TcbInfo tcb_info,
      absl::flat_hash_set<Tcb, absl::Hash<Tcb>, MessageEqual> tcb_levels);

  // The TCB info that this TcbInfoReader was created with.
  TcbInfo tcb_info_;

  // The TCB levels from the TCB info.
  absl::flat_hash_set<Tcb, absl::Hash<Tcb>, MessageEqual> tcb_levels_;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_TCB_INFO_READER_H_
