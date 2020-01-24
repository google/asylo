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

#include "asylo/identity/provisioning/sgx/internal/tcb_info_reader.h"

#include <functional>
#include <utility>

#include "absl/container/flat_hash_set.h"
#include "absl/hash/hash.h"
#include "absl/strings/str_cat.h"
#include "asylo/identity/provisioning/sgx/internal/container_util.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/identity/sgx/pck_certificate_util.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

StatusOr<TcbInfoReader> TcbInfoReader::Create(TcbInfo tcb_info) {
  ASYLO_RETURN_IF_ERROR(ValidateTcbInfo(tcb_info));
  absl::flat_hash_set<Tcb, absl::Hash<Tcb>, MessageEqual> tcb_levels;
  for (TcbLevel &tcb_level : *tcb_info.mutable_impl()->mutable_tcb_levels()) {
    tcb_levels.insert(std::move(*tcb_level.mutable_tcb()));
  }
  return TcbInfoReader(std::move(tcb_levels));
}

StatusOr<ProvisioningConsistency> TcbInfoReader::GetConsistencyWith(
    const PckCertificates &pck_certificates) const {
  ASYLO_RETURN_IF_ERROR(ValidatePckCertificates(pck_certificates));
  bool tcb_info_missing_level = !std::all_of(
      pck_certificates.certs().begin(), pck_certificates.certs().end(),
      [this](const PckCertificates::PckCertificateInfo &cert_info) {
        return tcb_levels_.contains(cert_info.tcb_level());
      });

  absl::flat_hash_set<Tcb, absl::Hash<Tcb>, MessageEqual>
      tcbs_from_certificates;
  tcbs_from_certificates.reserve(pck_certificates.certs().size());
  for (const auto &cert_info : pck_certificates.certs()) {
    tcbs_from_certificates.insert(cert_info.tcb_level());
  }
  bool certificates_missing_level =
      !std::all_of(tcb_levels_.begin(), tcb_levels_.end(),
                   [&tcbs_from_certificates](const Tcb &tcb) {
                     return tcbs_from_certificates.contains(tcb);
                   });

  if (tcb_info_missing_level) {
    if (certificates_missing_level) {
      return ProvisioningConsistency::kOtherInconsistency;
    } else {
      return ProvisioningConsistency::kTcbInfoStale;
    }
  } else {
    if (certificates_missing_level) {
      return ProvisioningConsistency::kPckCertificatesStale;
    } else {
      return ProvisioningConsistency::kConsistent;
    }
  }
}

TcbInfoReader::TcbInfoReader(
    absl::flat_hash_set<Tcb, absl::Hash<Tcb>, MessageEqual> tcb_levels)
    : tcb_levels_(std::move(tcb_levels)) {}

}  // namespace sgx
}  // namespace asylo
