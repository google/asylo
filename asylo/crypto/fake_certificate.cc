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

#include "asylo/crypto/fake_certificate.h"

#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/time/time.h"
#include "asylo/crypto/fake_certificate.pb.h"
#include "asylo/util/status_macros.h"

namespace asylo {

FakeCertificate::FakeCertificate(absl::string_view subject_key,
                                 absl::string_view issuer_key,
                                 absl::optional<bool> is_ca,
                                 absl::optional<int64_t> pathlength,
                                 absl::optional<std::string> subject_name)
    : subject_key_(subject_key),
      issuer_key_(issuer_key),
      is_ca_(is_ca),
      pathlength_(pathlength),
      subject_name_(subject_name) {}

StatusOr<std::unique_ptr<FakeCertificate>> FakeCertificate::Create(
    const Certificate &certificate) {
  FakeCertificateProto fake_cert;
  if (!fake_cert.ParseFromString(certificate.data())) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Could not parse certificate");
  }
  if (!fake_cert.has_subject_key()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Certificate must include subject key");
  }
  if (!fake_cert.has_issuer_key()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Certificate must include issuer key");
  }

  absl::optional<bool> is_ca = absl::nullopt;
  if (fake_cert.has_is_ca()) {
    is_ca = fake_cert.is_ca();
  }

  absl::optional<int64_t> pathlength = absl::nullopt;
  if (fake_cert.has_pathlength()) {
    pathlength = fake_cert.pathlength();
  }

  absl::optional<std::string> subject_name = absl::nullopt;
  if (fake_cert.has_subject_name()) {
    subject_name = fake_cert.subject_name();
  }

  return absl::make_unique<FakeCertificate>(fake_cert.subject_key(),
                                            fake_cert.issuer_key(), is_ca,
                                            pathlength, subject_name);
}

bool FakeCertificate::operator==(const CertificateInterface &other) const {
  const FakeCertificate *other_cert =
      dynamic_cast<FakeCertificate const *>(&other);
  if (other_cert == nullptr) {
    return false;
  }
  return subject_key_ == other_cert->subject_key_ &&
         issuer_key_ == other_cert->issuer_key_ &&
         is_ca_ == other_cert->is_ca_ &&
         pathlength_ == other_cert->pathlength_ &&
         subject_name_ == other_cert->subject_name_;
}

Status FakeCertificate::Verify(const CertificateInterface &issuer_certificate,
                               const VerificationConfig &config) const {
  std::string issuer_subject_key;
  ASYLO_ASSIGN_OR_RETURN(issuer_subject_key,
                         issuer_certificate.SubjectKeyDer());
  if (issuer_key_ != issuer_subject_key) {
    return Status(absl::StatusCode::kUnauthenticated,
                  absl::StrFormat("Verification failed: issuer's subject key "
                                  "(%s) is not the issuer key (%s)",
                                  issuer_subject_key, issuer_key_));
  }

  return absl::OkStatus();
}

StatusOr<std::string> FakeCertificate::SubjectKeyDer() const {
  return subject_key_;
}

absl::optional<std::string> FakeCertificate::SubjectName() const {
  return subject_name_;
}

absl::optional<bool> FakeCertificate::IsCa() const { return is_ca_; }

absl::optional<int64_t> FakeCertificate::CertPathLength() const {
  return pathlength_;
}

absl::optional<KeyUsageInformation> FakeCertificate::KeyUsage() const {
  return absl::nullopt;
}

StatusOr<bool> FakeCertificate::WithinValidityPeriod(
    const absl::Time &time) const {
  return true;
}

StatusOr<Certificate> FakeCertificate::ToCertificateProto(
    Certificate::CertificateFormat encoding) const {
  FakeCertificateProto fake_cert;
  fake_cert.set_subject_key(subject_key_);
  fake_cert.set_issuer_key(issuer_key_);
  if (is_ca_.has_value()) {
    fake_cert.set_is_ca(is_ca_.value());
  }
  if (pathlength_.has_value()) {
    fake_cert.set_pathlength(pathlength_.value());
  }
  if (subject_name_.has_value()) {
    fake_cert.set_subject_name(subject_name_.value());
  }

  Certificate cert;
  cert.set_format(encoding);
  if (!fake_cert.SerializeToString(cert.mutable_data())) {
    return Status(absl::StatusCode::kInternal,
                  "Failed to serialize FakeCertificateProto");
  }

  return cert;
}

}  // namespace asylo
