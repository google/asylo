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

#ifndef ASYLO_CRYPTO_X509_CERTIFICATE_H_
#define ASYLO_CRYPTO_X509_CERTIFICATE_H_

#include <openssl/base.h>
#include <openssl/x509.h>

#include <cstdint>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// An implementation of CertificateInterface that can parse and verify
// X.509 certificates from PEM or DER encodings.
class X509Certificate : public CertificateInterface {
 public:
  // Allocates memory for and initializes a new X509 object.
  X509Certificate();

  // Creates and returns an X509Certificate with the given |certificate| as
  // data. Returns a non-OK Status if the certificate could not be transformed
  // into a X509Certificate.
  static StatusOr<std::unique_ptr<X509Certificate>> Create(
      const Certificate &certificate);

  // Creates and returns an X509Certificate parsed from |pem_encoded_cert|.
  // Returns a non-OK Status if the data could not be parsed into X.509.
  static StatusOr<std::unique_ptr<X509Certificate>> CreateFromPem(
      absl::string_view pem_encoded_cert);

  // Creates and returns an X509Certificate parsed from |der_encoded_cert|.
  // Returns a non-OK Status if the data could not be parsed into X.509.
  static StatusOr<std::unique_ptr<X509Certificate>> CreateFromDer(
      absl::string_view der_encoded_cert);

  // Creates and returns a PEM-formatted certificate equivalent to the data in
  // this object. Returns a non-OK Status if the object could not be
  // transformed.
  StatusOr<Certificate> ToPemCertificate() const;

  // From CertificateInterface.

  // Based on |config|, checks if |issuer_certificate| is a CA certificate with
  // key usage for certificate signing. It is not an authentication failure if
  // either of these extensions are not set.
  Status Verify(const CertificateInterface &issuer_certificate,
                const VerificationConfig &config) const override;

  StatusOr<std::string> SubjectKeyDer() const override;

  absl::optional<bool> IsCa() const override;

  absl::optional<int64_t> CertPathLength() const override;

  absl::optional<KeyUsageInformation> KeyUsage() const override;

 private:
  explicit X509Certificate(bssl::UniquePtr<X509> x509);

  bssl::UniquePtr<X509> x509_;
};

// Creates and returns an X509_REQ object equivalent to the data in |csr|.
// Returns a non-OK Status if the certificate signing request could not be
// transformed to the equivalent X509_REQ object.
StatusOr<bssl::UniquePtr<X509_REQ>> CertificateSigningRequestToX509Req(
    const CertificateSigningRequest &csr);

// Creates and returns a DER-formatted certificate signing request equivalent
// to the data in |x509_req|. Returns a non-OK Status if the X509_REQ object
// could not be transformed.
StatusOr<CertificateSigningRequest> X509ReqToDerCertificateSigningRequest(
    const X509_REQ &x509_req);

// Returns the DER-encoded subject key of |csr|. Returns a non-OK Status if
// there was an error.
StatusOr<std::string> ExtractPkcs10SubjectKeyDer(
    const CertificateSigningRequest &csr);

}  // namespace asylo

#endif  // ASYLO_CRYPTO_X509_CERTIFICATE_H_
