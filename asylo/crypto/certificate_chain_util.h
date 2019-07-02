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

#ifndef ASYLO_CRYPTO_CERTIFICATE_CHAIN_UTIL_H_
#define ASYLO_CRYPTO_CERTIFICATE_CHAIN_UTIL_H_

#include <memory>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_util_interface.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// Utilities for a certificate chain, where each certificate is parsed and
// verified using a certificate util passed in through AddCertificateUtil(). An
// example use case:
//
//   CertificateChainUtil chain_util;
//   chain_util.AddCertificateUtil(
//      Certificate::X1, absl::make_unique<XCertificateUtil>());
//   chain_util.AddCertificateUtil(
//      Certificate::X2, absl::make_unique<XCertificateUtil>());
//   chain_util.AddCertificateUtil(
//      Certificate::Y, absl::make_unique<YCertificateUtil>());
//
//   CertificateChain chain = ...;
//   if (chain_util.VerifyCertificateChain(chain).ok()) {
//     // Certificate chain is valid
//     ...
//    }
//
// This class is thread compatible if the added certificate utilities are
// thread compatible.
class CertificateChainUtil {
 public:
  // Adds |format| -> |util| mapping, such that this object verifies and parses
  // certificates of format |format| using |util|. If there already exists a
  // util for |format|, does not modify the existing mapping and returns
  // false. If the mapping is set successfully, returns true.
  bool AddCertificateUtil(Certificate::CertificateFormat format,
                          std::unique_ptr<CertificateUtilInterface> util);

  // Checks if |certificate_chain| is a valid chain of certificates. The last
  // certificate must be self-signed. Returns a non-OK Status if the certificate
  // chain is invalid, or if there were errors while verifying.
  Status VerifyCertificateChain(
      const CertificateChain &certificate_chain) const;

  // Extracts the DER-encoded subject key of the end-user certificate. Returns
  // a non-OK Status if there were errors while parsing.
  StatusOr<std::string> GetEndUserSubjectKey(
      const CertificateChain &certificate_chain) const;

 private:
  // Returns a pointer to the CertificateUtilInterface |format| maps to, or a
  // non-OK Status if there was no mapping.
  StatusOr<const CertificateUtilInterface *> GetUtil(
      Certificate::CertificateFormat format) const;

  // Maps a certificate format to a certificate util.
  absl::flat_hash_map<Certificate::CertificateFormat,
                      std::unique_ptr<CertificateUtilInterface>>
      utils_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_CERTIFICATE_CHAIN_UTIL_H_
