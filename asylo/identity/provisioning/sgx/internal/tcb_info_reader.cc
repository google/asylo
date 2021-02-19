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
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/container_util.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certificate_util.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

// The index of the Configuration ID byte in a CPU SVN for TCB type 0.
constexpr int kConfigIdByteIndexForTcbType0 = 6;

}  // namespace

StatusOr<TcbInfoReader> TcbInfoReader::Create(TcbInfo tcb_info) {
  ASYLO_RETURN_IF_ERROR(ValidateTcbInfo(tcb_info));
  absl::flat_hash_set<Tcb, absl::Hash<Tcb>, MessageEqual> tcb_levels;
  for (const TcbLevel &tcb_level : tcb_info.impl().tcb_levels()) {
    tcb_levels.insert(tcb_level.tcb());
  }
  return TcbInfoReader(std::move(tcb_info), std::move(tcb_levels));
}

const TcbInfo &TcbInfoReader::GetTcbInfo() const { return tcb_info_; }

StatusOr<ConfigurationId> TcbInfoReader::GetConfigurationId(
    const CpuSvn &cpu_svn) const {
  ASYLO_RETURN_IF_ERROR(ValidateCpuSvn(cpu_svn));
  ConfigurationId config_id;
  switch (tcb_info_.impl().has_tcb_type() ? tcb_info_.impl().tcb_type()
                                          : TcbType::TCB_TYPE_0) {
    case TcbType::TCB_TYPE_0:
      config_id.set_value(cpu_svn.value()[kConfigIdByteIndexForTcbType0]);
      break;
    default:
      return Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Unknown TCB type: ",
                       ProtoEnumValueName(tcb_info_.impl().tcb_type())));
  }
  return config_id;
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
    TcbInfo tcb_info,
    absl::flat_hash_set<Tcb, absl::Hash<Tcb>, MessageEqual> tcb_levels)
    : tcb_info_(std::move(tcb_info)), tcb_levels_(std::move(tcb_levels)) {}

}  // namespace sgx
}  // namespace asylo
