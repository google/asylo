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

#include <cstdint>
#include <utility>

#include "absl/types/optional.h"
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

StatusOr<CertificateInterfaceVector> CreateCertificateChain(
    const CertificateFactoryMap &factory_map, const CertificateChain &chain) {
  CertificateInterfaceVector certificate_interface_chain;
  certificate_interface_chain.reserve(chain.certificates_size());
  for (int i = 0; i < chain.certificates_size(); i++) {
    const Certificate &cert = chain.certificates(i);
    auto factory_iter = factory_map.find(cert.format());
    if (factory_iter == factory_map.end()) {
      return Status(
          error::GoogleError::INVALID_ARGUMENT,
          absl::StrCat("At index ", i,
                       " no mapping from format to factory for format ",
                       Certificate_CertificateFormat_Name(cert.format())));
    }
    auto certificate_result = (factory_iter->second)(cert);
    if (!certificate_result.ok()) {
      return certificate_result.status().WithPrependedContext(
          absl::StrCat("Failed to create certificate at index ", i));
    }

    certificate_interface_chain.push_back(
        std::move(certificate_result).ValueOrDie());
  }
  return std::move(certificate_interface_chain);
}

Status VerifyCertificateChain(CertificateInterfaceSpan certificate_chain,
                              const VerificationConfig &verification_config) {
  if (certificate_chain.empty()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Certificate chain must include at least one certificate");
  }

  // For each certificate in the chain (except the root), verifies the
  // certificate with the issuer certificate. In the certificate list, the
  // issuer is the certificate next in the list after the certificate being
  // verified.
  int64_t ca_count = 0;
  for (int i = 0; i < certificate_chain.size() - 1; i++) {
    const CertificateInterface *subject = certificate_chain[i].get();
    const CertificateInterface *issuer = certificate_chain[i + 1].get();
    if (verification_config.max_pathlen) {
      absl::optional<int64_t> max_pathlength = issuer->CertPathLength();
      if (max_pathlength.has_value() && max_pathlength.value() < ca_count) {
        return asylo::Status(
            error::GoogleError::UNAUTHENTICATED,
            absl::StrCat(
                "Maximum pathlength of certificate at index ", i,
                " exceeded. Maximum pathlength: ", max_pathlength.value(),
                ", current pathlength: ", ca_count));
      }
    }
    absl::optional<bool> issuer_is_ca = issuer->IsCa();
    if (issuer_is_ca.value_or(true)) {
      ca_count++;
    }

    Status status = subject->Verify(*issuer, verification_config);
    if (!status.ok()) {
      return status.WithPrependedContext(
          absl::StrCat("Failed to verify certificate at index ", i));
    }
  }

  const CertificateInterface *root = certificate_chain.rbegin()->get();

  // Root certificate should be self-signed.
  Status status = root->Verify(*root, verification_config);
  if (!status.ok()) {
    return status.WithPrependedContext("Failed to verify root certificate");
  }

  return Status::OkStatus();
}

}  // namespace asylo
