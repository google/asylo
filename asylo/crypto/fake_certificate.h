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

#ifndef ASYLO_CRYPTO_FAKE_CERTIFICATE_H_
#define ASYLO_CRYPTO_FAKE_CERTIFICATE_H_

#include <cstdint>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// A fake implementation of CertificateInterface.
class FakeCertificate : public CertificateInterface {
 public:
  FakeCertificate(absl::string_view subject_key, absl::string_view issuer_key,
                  absl::optional<bool> is_ca,
                  absl::optional<int64_t> pathlength,
                  absl::optional<std::string> subject_name);

  // Creates a fake certificate. |certificate|.format() can be any value.
  // |certificate|.data() must be a serialized FakeCertificateProto.
  static StatusOr<std::unique_ptr<FakeCertificate>> Create(
      const Certificate &certificate);

  // From CertificateInterface.

  bool operator==(const CertificateInterface &other) const override;

  // Returns an OK Status if |issuer_certificate|.SubjectKeyDer() = issuer_key_.
  Status Verify(const CertificateInterface &issuer_certificate,
                const VerificationConfig &config) const override;

  StatusOr<std::string> SubjectKeyDer() const override;

  absl::optional<std::string> SubjectName() const override;

  absl::optional<bool> IsCa() const override;

  absl::optional<int64_t> CertPathLength() const override;

  // Returns absl::nullopt.
  absl::optional<KeyUsageInformation> KeyUsage() const override;

  // Returns true.
  StatusOr<bool> WithinValidityPeriod(const absl::Time &time) const override;

  StatusOr<Certificate> ToCertificateProto(
      Certificate::CertificateFormat encoding) const override;

 private:
  std::string subject_key_;
  std::string issuer_key_;
  absl::optional<bool> is_ca_;
  absl::optional<int64_t> pathlength_;
  absl::optional<std::string> subject_name_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_FAKE_CERTIFICATE_H_
