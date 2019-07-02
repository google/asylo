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

#include "asylo/crypto/certificate_chain_util.h"

#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/certificate_util_interface.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

// Prepends |context| to the error message of |original_status| then returns.
Status WithContext(const Status &original_status, absl::string_view context) {
  return Status(original_status.error_space(), original_status.error_code(),
                absl::StrCat(context, ": ", original_status.error_message()));
}

}  // namespace

bool CertificateChainUtil::AddCertificateUtil(
    Certificate::CertificateFormat format,
    std::unique_ptr<CertificateUtilInterface> util) {
  return utils_.emplace(format, std::move(util)).second;
}

Status CertificateChainUtil::VerifyCertificateChain(
    const CertificateChain &certificate_chain) const {
  if (certificate_chain.certificates().empty()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Certificate chain must include at least one certificate");
  }

  // Set up list of certificate utils.
  std::vector<const CertificateUtilInterface *> utils;
  utils.reserve(certificate_chain.certificates_size());
  for (int i = 0; i < certificate_chain.certificates_size(); i++) {
    auto util_result = GetUtil(certificate_chain.certificates(i).format());
    if (!util_result.ok()) {
      return WithContext(util_result.status(), absl::StrCat("At index ", i));
    }
    utils.push_back(util_result.ValueOrDie());
  }

  // For each certificate in the chain (except the root), verifies that the
  // certificate was signed with the private key corresponding to the issuer's
  // subject key. In the certificate list, the issuer is the certificate next in
  // the list after the certificate being verified.
  for (int i = 0; i < certificate_chain.certificates_size() - 1; i++) {
    const Certificate &issuer = certificate_chain.certificates(i + 1);
    auto issuer_public_key_der_result =
        utils[i + 1]->ExtractSubjectKeyDer(issuer);
    if (!issuer_public_key_der_result.ok()) {
      return WithContext(
          issuer_public_key_der_result.status(),
          absl::StrCat(
              "Failed to extract public key from certificate at index ",
              i + 1));
    }

    const Certificate &subject = certificate_chain.certificates(i);
    Status status = utils[i]->VerifyCertificate(
        subject, issuer_public_key_der_result.ValueOrDie());
    if (!status.ok()) {
      return WithContext(
          status, absl::StrCat("Failed to verify certificate at index ", i));
    }
  }

  const Certificate &root = *certificate_chain.certificates().rbegin();
  const CertificateUtilInterface *root_util = *utils.rbegin();

  auto public_key_der_result = root_util->ExtractSubjectKeyDer(root);
  if (!public_key_der_result.ok()) {
    return WithContext(public_key_der_result.status(),
                       "Failed to extract public key from root certificate");
  }

  // Root certificate should be self-signed.
  Status status =
      root_util->VerifyCertificate(root, public_key_der_result.ValueOrDie());
  if (!status.ok()) {
    return WithContext(status, "Failed to verify root certificate");
  }

  return Status::OkStatus();
}

StatusOr<std::string> CertificateChainUtil::GetEndUserSubjectKey(
    const CertificateChain &certificate_chain) const {
  auto end_cert = certificate_chain.certificates().cbegin();
  if (end_cert == certificate_chain.certificates().end()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Certificate chain must include at least one certificate");
  }

  const CertificateUtilInterface *util;
  ASYLO_ASSIGN_OR_RETURN(util, GetUtil(end_cert->format()));
  return util->ExtractSubjectKeyDer(*end_cert);
}

StatusOr<const CertificateUtilInterface *> CertificateChainUtil::GetUtil(
    Certificate::CertificateFormat format) const {
  auto util_it = utils_.find(format);
  if (util_it == utils_.end()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrCat("No mapping from format to util for format ",
                               Certificate_CertificateFormat_Name(format)));
  }
  return util_it->second.get();
}

}  // namespace asylo
