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
#include "asylo/crypto/x509_certificate.h"

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <limits>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/logging.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

constexpr int kX509Version3 = 2;

// Creates a public key object using the signature algorithm in |certificate|
// and the public key data in |public_key_der|. Returns a non-OK Status if the
// signature algorithm or key type are unsupported, or if an error occurred.
StatusOr<bssl::UniquePtr<EVP_PKEY>> CreatePublicKey(
    const X509 *certificate, ByteContainerView public_key_der) {
  // Translate the signature algorithm.
  int signature_id = X509_get_signature_nid(certificate);

  bssl::UniquePtr<EVP_PKEY> evp_key(EVP_PKEY_new());

  // Parse the public key information into evp_key.
  switch (signature_id) {
    case NID_ecdsa_with_SHA256: {
      uint8_t const *public_key_data = public_key_der.data();

      // Create a public key from the input data. If |a| was set, the EC_KEY
      // object referenced by |a| would be freed and |a| would be updated to
      // point to the returned object.
      bssl::UniquePtr<EC_KEY> ec_key(d2i_EC_PUBKEY(
          /*a=*/nullptr, &public_key_data, public_key_der.size()));
      if (!ec_key) {
        return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
      }

      if (EVP_PKEY_assign_EC_KEY(evp_key.get(), ec_key.release()) != 1) {
        return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
      }

      return std::move(evp_key);
    }
    default: {
      std::string signature_name;
      const char *data = OBJ_nid2sn(signature_id);
      if (data == nullptr) {
        signature_name = absl::StrCat("signature with NID ", signature_id);
        LOG(ERROR) << "Could not parse name for " << signature_name;
      } else {
        signature_name = data;
      }
      return Status(
          error::GoogleError::UNIMPLEMENTED,
          absl::StrCat("Signature algorithm not supported: ", signature_name));
    }
  }
}

// Returns the DER-encoding of |evp_key|.
StatusOr<std::string> EvpPkeyToDer(const EVP_PKEY &evp_key) {
  bssl::UniquePtr<BIO> key_bio(BIO_new(BIO_s_mem()));
  if (i2d_PUBKEY_bio(key_bio.get(), const_cast<EVP_PKEY *>(&evp_key)) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  char *public_key_data = nullptr;
  int64_t public_key_length = BIO_get_mem_data(key_bio.get(), &public_key_data);
  if (public_key_length <= 0) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return std::string(public_key_data, public_key_length);
}

}  // namespace

X509Certificate::X509Certificate() : x509_(CHECK_NOTNULL(X509_new())) {}

StatusOr<std::unique_ptr<X509Certificate>> X509Certificate::Create(
    const Certificate &certificate) {
  switch (certificate.format()) {
    case Certificate::X509_PEM:
      return CreateFromPem(certificate.data());
    case Certificate::X509_DER:
      return CreateFromDer(certificate.data());
    default:
      return Status(
          error::GoogleError::INVALID_ARGUMENT,
          absl::StrCat(
              "Transformation to X509 is not supported for: ",
              Certificate_CertificateFormat_Name(certificate.format())));
  }
}

StatusOr<std::unique_ptr<X509Certificate>> X509Certificate::CreateFromPem(
    absl::string_view pem_encoded_cert) {
  bssl::UniquePtr<BIO> cert_bio(
      BIO_new_mem_buf(pem_encoded_cert.data(), pem_encoded_cert.size()));
  bssl::UniquePtr<X509> x509(PEM_read_bio_X509(cert_bio.get(), /*x=*/nullptr,
                                               /*cb=*/nullptr,
                                               /*u=*/nullptr));
  if (x509 == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return absl::WrapUnique<X509Certificate>(
      new X509Certificate(std::move(x509)));
}

StatusOr<std::unique_ptr<X509Certificate>> X509Certificate::CreateFromDer(
    absl::string_view der_encoded_cert) {
  bssl::UniquePtr<BIO> cert_bio(
      BIO_new_mem_buf(der_encoded_cert.data(), der_encoded_cert.size()));
  bssl::UniquePtr<X509> x509(d2i_X509_bio(cert_bio.get(), /*x509=*/nullptr));
  if (x509 == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return absl::WrapUnique<X509Certificate>(
      new X509Certificate(std::move(x509)));
}

StatusOr<Certificate> X509Certificate::ToPemCertificate() const {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_X509(bio.get(), x509_.get())) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  char *data;
  long length = BIO_get_mem_data(bio.get(), &data);
  if (length <= 0) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  Certificate cert;
  cert.set_format(Certificate::X509_PEM);
  cert.set_data(data, length);
  return cert;
}

StatusOr<bssl::UniquePtr<X509_REQ>> CertificateSigningRequestToX509Req(
    const CertificateSigningRequest &csr) {
  bssl::UniquePtr<BIO> csr_bio(
      BIO_new_mem_buf(csr.data().data(), csr.data().size()));
  bssl::UniquePtr<X509_REQ> req;
  switch (csr.format()) {
    case CertificateSigningRequest::PKCS10_PEM:
      req.reset(PEM_read_bio_X509_REQ(csr_bio.get(), /*x=*/nullptr,
                                      /*cb=*/nullptr,
                                      /*u=*/nullptr));
      break;
    case CertificateSigningRequest::PKCS10_DER:
      req.reset(d2i_X509_REQ_bio(csr_bio.get(), /*req=*/nullptr));
      break;
    default:
      return Status(
          error::GoogleError::INVALID_ARGUMENT,
          absl::StrCat(
              "Transformation to X509_REQ not suported for: ",
              CertificateSigningRequest_CertificateSigningRequestFormat_Name(
                  csr.format())));
  }
  if (req == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return std::move(req);
}

StatusOr<CertificateSigningRequest> X509ReqToDerCertificateSigningRequest(
    const X509_REQ &x509_req) {
  bssl::UniquePtr<BIO> x509_bio(BIO_new(BIO_s_mem()));
  if (i2d_X509_REQ_bio(x509_bio.get(), const_cast<X509_REQ *>(&x509_req)) !=
      1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  char *data;
  long length = BIO_get_mem_data(x509_bio.get(), &data);
  if (length <= 0) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::PKCS10_DER);
  csr.set_data(data, length);
  return csr;
}

StatusOr<std::string> ExtractPkcs10SubjectKeyDer(
    const CertificateSigningRequest &csr) {
  bssl::UniquePtr<X509_REQ> x509_req;
  ASYLO_ASSIGN_OR_RETURN(x509_req, CertificateSigningRequestToX509Req(csr));

  bssl::UniquePtr<EVP_PKEY> public_key(X509_REQ_get_pubkey(x509_req.get()));
  if (public_key == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return EvpPkeyToDer(*public_key);
}

Status X509Certificate::Verify(const CertificateInterface &issuer_certificate,
                               const VerificationConfig &config) const {
  std::string issuer_public_key_der;
  ASYLO_ASSIGN_OR_RETURN(issuer_public_key_der,
                         issuer_certificate.SubjectKeyDer());
  bssl::UniquePtr<EVP_PKEY> public_key;
  ASYLO_ASSIGN_OR_RETURN(public_key,
                         CreatePublicKey(x509_.get(), issuer_public_key_der));

  if (X509_verify(x509_.get(), public_key.get()) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  if (config.issuer_ca) {
    absl::optional<bool> issuer_is_ca = issuer_certificate.IsCa();
    if (issuer_is_ca.has_value() && !issuer_is_ca.value()) {
      return Status(error::GoogleError::UNAUTHENTICATED,
                    "Issuer had a CA extension value of false");
    }
  }

  if (config.issuer_key_usage) {
    absl::optional<KeyUsageInformation> key_usage =
        issuer_certificate.KeyUsage();
    if (key_usage.has_value() && !key_usage.value().certificate_signing) {
      return Status(
          error::GoogleError::UNAUTHENTICATED,
          "Issuer's key usage extension did not include certificate signing");
    }
  }

  return Status::OkStatus();
}

StatusOr<std::string> X509Certificate::SubjectKeyDer() const {
  bssl::UniquePtr<EVP_PKEY> evp_key(X509_get_pubkey(x509_.get()));
  if (evp_key == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return EvpPkeyToDer(*evp_key);
}

absl::optional<bool> X509Certificate::IsCa() const {
  // Version 3 of X.509 introduces standard extensions.
  if (X509_get_version(x509_.get()) != kX509Version3) {
    return absl::nullopt;
  }
  return X509_check_ca(x509_.get()) != 0;
}

absl::optional<int64_t> X509Certificate::CertPathLength() const {
  // Code is copied from implementation of X509_get_pathlen. X509_check_purpose
  // is used to recalculate and populate the extension flags. EXFLAG_BCONS
  // is set in the extension flags if the certificate contains a basic
  // constraints extension, which includes the maximum allowed pathlength.
  if (X509_check_purpose(x509_.get(), /*id=*/-1, /*ca=*/-1) != 1 ||
      (x509_->ex_flags & EXFLAG_BCONS) == 0) {
    return absl::nullopt;
  }

  long pathlength = x509_->ex_pathlen;

  if (pathlength > std::numeric_limits<int64_t>::max() ||
      pathlength < std::numeric_limits<int64_t>::min()) {
    LOG(ERROR) << "Pathlength is outside of the return value's limits: "
               << pathlength;
    return absl::nullopt;
  }

  // If pathlength is -1, the extension value is not present
  // (https://www.openssl.org/docs/man1.1.0/man3/X509_get_pathlen.html)
  if (pathlength == -1) {
    return absl::nullopt;
  }

  return pathlength;
}

absl::optional<KeyUsageInformation> X509Certificate::KeyUsage() const {
  uint32_t key_usage_values = X509_get_key_usage(x509_.get());
  if (key_usage_values == std::numeric_limits<uint32_t>::max()) {
    return absl::nullopt;
  }
  KeyUsageInformation key_usage;
  key_usage.certificate_signing = key_usage_values & KU_KEY_CERT_SIGN;
  key_usage.crl_signing = key_usage_values & KU_CRL_SIGN;
  key_usage.digital_signature = key_usage_values & KU_DIGITAL_SIGNATURE;
  return key_usage;
}

X509Certificate::X509Certificate(bssl::UniquePtr<X509> x509)
    : x509_(std::move(x509)) {}

}  // namespace asylo
