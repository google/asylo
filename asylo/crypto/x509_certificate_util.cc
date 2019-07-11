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
#include "asylo/crypto/x509_certificate_util.h"

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdint>
#include <utility>

#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

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

}  // namespace

StatusOr<bssl::UniquePtr<X509>> X509CertificateUtil::CertificateToX509(
    const Certificate &certificate) {
  bssl::UniquePtr<BIO> cert_bio(
      BIO_new_mem_buf(certificate.data().data(), certificate.data().size()));
  bssl::UniquePtr<X509> x509;
  switch (certificate.format()) {
    case Certificate::X509_PEM:
      x509.reset(PEM_read_bio_X509(cert_bio.get(), /*x=*/nullptr,
                                   /*cb=*/nullptr,
                                   /*u=*/nullptr));
      break;
    case Certificate::X509_DER:
      x509.reset(d2i_X509_bio(cert_bio.get(), /*x509=*/nullptr));
      break;
    default:
      return Status(
          error::GoogleError::INVALID_ARGUMENT,
          absl::StrCat(
              "Transformation to X509 is not supported for: ",
              Certificate_CertificateFormat_Name(certificate.format())));
  }
  if (x509 == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return std::move(x509);
}

StatusOr<Certificate> X509CertificateUtil::X509ToPemCertificate(
    const X509 &x509) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_X509(bio.get(), const_cast<X509 *>(&x509))) {
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

Status X509CertificateUtil::VerifyCertificate(
    const Certificate &certificate, ByteContainerView public_key_der) const {
  bssl::UniquePtr<X509> x509;
  ASYLO_ASSIGN_OR_RETURN(x509, CertificateToX509(certificate));

  bssl::UniquePtr<EVP_PKEY> public_key;
  ASYLO_ASSIGN_OR_RETURN(public_key,
                         CreatePublicKey(x509.get(), public_key_der));

  if (X509_verify(x509.get(), public_key.get()) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return Status::OkStatus();
}

StatusOr<std::string> X509CertificateUtil::ExtractSubjectKeyDer(
    const Certificate &certificate) const {
  bssl::UniquePtr<X509> x509;
  ASYLO_ASSIGN_OR_RETURN(x509, CertificateToX509(certificate));

  bssl::UniquePtr<EVP_PKEY> evp_key(X509_get_pubkey(x509.get()));
  if (evp_key == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  bssl::UniquePtr<BIO> key_bio(BIO_new(BIO_s_mem()));
  if (i2d_PUBKEY_bio(key_bio.get(), evp_key.get()) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  char *public_key_data = nullptr;
  int64_t public_key_length = BIO_get_mem_data(key_bio.get(), &public_key_data);
  if (public_key_length <= 0) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return std::string(public_key_data, public_key_length);
}

}  // namespace asylo
