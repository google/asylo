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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_ATTESTATION_KEY_CERTIFICATE_IMPL_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_ATTESTATION_KEY_CERTIFICATE_IMPL_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key.pb.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate.pb.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// A CertificateInterface implementation for parsing and verifying
// AttestationKeyCertificate proto messages.
class AttestationKeyCertificateImpl : public CertificateInterface {
 public:
  // Creates and returns an AttestationKeyCertificateImpl with the given
  // |certificate| as data. Returns a non-OK Status if the certificate could not
  // be transformed into an AttestationKeyCertificateImpl or if any fields are
  // missing. Additionally checks that the certificate is well-formed based on
  // the requirements for the AttestationKeyCertificate proto message.
  static StatusOr<std::unique_ptr<AttestationKeyCertificateImpl>> Create(
      const Certificate &certificate);

  // Extracts the SgxIdentity asserted by the serialized Report in the
  // certificate.
  SgxIdentity GetAssertedSgxIdentity() const;

  // From CertificateInterface.

  // Compares the underlying proto message representations of the certificates.
  // Returns false if the signatures are different, even if the rest of the data
  // is the same.
  bool operator==(const CertificateInterface &other) const override;

  Status Verify(const CertificateInterface &issuer_certificate,
                const VerificationConfig &config) const override;

  StatusOr<std::string> SubjectKeyDer() const override;

  absl::optional<std::string> SubjectName() const override;

  absl::optional<bool> IsCa() const override;

  absl::optional<int64_t> CertPathLength() const override;

  absl::optional<KeyUsageInformation> KeyUsage() const override;

  StatusOr<bool> WithinValidityPeriod(const absl::Time &time) const override;

  StatusOr<Certificate> ToCertificateProto(
      Certificate::CertificateFormat encoding) const override;

 private:
  explicit AttestationKeyCertificateImpl(
      AttestationKeyCertificate attestation_key_cert,
      AsymmetricSigningKeyProto subject_key, Report report);

  const AttestationKeyCertificate attestation_key_cert_;

  const AsymmetricSigningKeyProto subject_key_;

  const Report report_;
};

// Creates a Certificate containing an embedded AttestationKeyCertificate.
StatusOr<Certificate> CreateAttestationKeyCertificate(
    ReportProto report, Signature signature,
    std::string pce_sign_report_payload);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_ATTESTATION_KEY_CERTIFICATE_IMPL_H_
