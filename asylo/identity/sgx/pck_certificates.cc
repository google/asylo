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

#include "asylo/identity/sgx/pck_certificates.h"

#include <string>

#include <google/protobuf/util/message_differencer.h>
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/identity/sgx/platform_provisioning.pb.h"
#include "asylo/identity/sgx/tcb.h"
#include "asylo/identity/sgx/tcb.pb.h"
#include "asylo/identity/sgx/tcb_container_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace {

// Validates a PckCertificates.PckCertificateInfo message.
Status ValidatePckCertificateInfo(
    const PckCertificates::PckCertificateInfo &cert_info) {
  if (!cert_info.has_tcb_level()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "PckCertificateInfo does not have a \"tcb_level\" field");
  }
  if (!cert_info.has_tcbm()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "PckCertificateInfo does not have a \"tcbm\" field");
  }
  if (!cert_info.has_cert()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "PckCertificateInfo does not have a \"cert\" field");
  }

  ASYLO_RETURN_IF_ERROR(ValidateTcb(cert_info.tcb_level()));
  ASYLO_RETURN_IF_ERROR(ValidateRawTcb(cert_info.tcbm()));
  ASYLO_RETURN_IF_ERROR(ValidateCertificate(cert_info.cert()));

  if (!google::protobuf::util::MessageDifferencer::Equals(cert_info.tcb_level().pce_svn(),
                                                cert_info.tcbm().pce_svn())) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "PckCertificateInfo has two different PCE SVNs");
  }

  return Status::OkStatus();
}

}  // namespace

Status ValidatePckCertificates(const PckCertificates &pck_certificates) {
  absl::flat_hash_map<Tcb, const PckCertificates::PckCertificateInfo *, TcbHash,
                      TcbEqual>
      tcbs_to_certs;
  absl::flat_hash_set<RawTcb, RawTcbHash, RawTcbEqual> tcbms;
  for (const auto &cert_info : pck_certificates.certs()) {
    ASYLO_RETURN_IF_ERROR(ValidatePckCertificateInfo(cert_info));

    auto it = tcbs_to_certs.find(cert_info.tcb_level());
    if (it != tcbs_to_certs.end()) {
      if (!google::protobuf::util::MessageDifferencer::Equals(*it->second, cert_info)) {
        return Status(
            error::GoogleError::INVALID_ARGUMENT,
            "PckCertificates contains two distinct entries with identical "
            "TCBs");
      } else {
        continue;
      }
    }

    if (tcbms.contains(cert_info.tcbm())) {
      return Status(
          error::GoogleError::INVALID_ARGUMENT,
          "PckCertificates contains two distinct entries with identical TCBMs");
    }

    tcbs_to_certs.emplace(cert_info.tcb_level(), &cert_info);
    tcbms.insert(cert_info.tcbm());
  }

  return Status::OkStatus();
}

}  // namespace sgx
}  // namespace asylo
