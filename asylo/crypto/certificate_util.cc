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

#include "asylo/crypto/certificate_util.h"

#include "asylo/util/status_macros.h"

namespace asylo {

Status ValidateCertificateSigningRequest(const CertificateSigningRequest &csr) {
  if (!csr.has_format()) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        "CertificateSigningRequest missing required \"format\" field");
  }
  if (!csr.has_data()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "CertificateSigningRequest missing required \"data\" field");
  }
  if (csr.format() == asylo::CertificateSigningRequest::UNKNOWN) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "CertificateSigningRequest has an unknown format");
  }

  return Status::OkStatus();
}

Status ValidateCertificate(const Certificate &certificate) {
  if (!certificate.has_format()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Certificate missing required \"format\" field");
  }
  if (!certificate.has_data()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Certificate missing required \"data\" field");
  }
  if (certificate.format() == asylo::Certificate::UNKNOWN) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Certificate has an unknown format");
  }

  return Status::OkStatus();
}

Status ValidateCertificateChain(const CertificateChain &certificate_chain) {
  for (const auto &certificate : certificate_chain.certificates()) {
    ASYLO_RETURN_IF_ERROR(ValidateCertificate(certificate));
  }

  return Status::OkStatus();
}

Status ValidateCertificateRevocationList(const CertificateRevocationList &crl) {
  if (!crl.has_format()) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        "CertificateRevocationList missing required \"format\" field");
  }
  if (!crl.has_data()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "CertificateRevocationList missing required \"data\" field");
  }
  if (crl.format() == asylo::CertificateRevocationList::UNKNOWN) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "CertificateRevocationList has an unknown format");
  }

  return Status::OkStatus();
}

}  // namespace asylo
