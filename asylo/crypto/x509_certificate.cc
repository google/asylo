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

#include <openssl/asn1.h>
#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/obj.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/call_once.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/x509_signer.h"
#include "asylo/util/logging.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

// The indices of bits in a ReasonFlags BIT STRING.
enum ReasonBitIndices {
  KEY_COMPROMISE = 1,
  CA_COMPROMISE = 2,
  AFFILIATION_CHANGED = 3,
  SUPERSEDED = 4,
  CESSATION_OF_OPERATION = 5,
  CERTIFICATE_HOLD = 6,
  PRIVILEDGE_WITHDRAWN = 7,
  AA_COMPROMISE = 8,
};

// The maximum size of a ReasonFlags BIT STRING.
constexpr int kReasonFlagsMaxSize = 9;

// Converts |reasons| to a bit-vector and a flagset, represented as a
// std::vector<bool> and an int, respectively.
std::pair<std::vector<bool>, int> ReasonsToBitvecAndFlags(
    CrlDistributionPoints::Reasons reasons) {
  std::vector<bool> bitvec(kReasonFlagsMaxSize, false);
  int flags = 0;
  if (reasons.key_compromise) {
    bitvec[ReasonBitIndices::KEY_COMPROMISE] = true;
    flags |= 1 << ReasonBitIndices::KEY_COMPROMISE;
  }
  if (reasons.ca_compromise) {
    bitvec[ReasonBitIndices::CA_COMPROMISE] = true;
    flags |= 1 << ReasonBitIndices::CA_COMPROMISE;
  }
  if (reasons.affiliation_changed) {
    bitvec[ReasonBitIndices::AFFILIATION_CHANGED] = true;
    flags |= 1 << ReasonBitIndices::AFFILIATION_CHANGED;
  }
  if (reasons.superseded) {
    bitvec[ReasonBitIndices::SUPERSEDED] = true;
    flags |= 1 << ReasonBitIndices::SUPERSEDED;
  }
  if (reasons.cessation_of_operation) {
    bitvec[ReasonBitIndices::CESSATION_OF_OPERATION] = true;
    flags |= 1 << ReasonBitIndices::CESSATION_OF_OPERATION;
  }
  if (reasons.certificate_hold) {
    bitvec[ReasonBitIndices::CERTIFICATE_HOLD] = true;
    flags |= 1 << ReasonBitIndices::CERTIFICATE_HOLD;
  }
  if (reasons.priviledge_withdrawn) {
    bitvec[ReasonBitIndices::PRIVILEDGE_WITHDRAWN] = true;
    flags |= 1 << ReasonBitIndices::PRIVILEDGE_WITHDRAWN;
  }
  if (reasons.aa_compromise) {
    bitvec[ReasonBitIndices::AA_COMPROMISE] = true;
    flags |= 1 << ReasonBitIndices::AA_COMPROMISE;
  }
  return {bitvec, flags};
}

// Converts |bitvec| to a CrlDistributionPoints::Reasons.
StatusOr<CrlDistributionPoints::Reasons> BitvecToReasons(
    std::vector<bool> bitvec) {
  if (bitvec.size() > kReasonFlagsMaxSize || (!bitvec.empty() && bitvec[0])) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat(
            "DistributionPoint contains unrecognized reason flags: {%s}",
            absl::StrJoin(bitvec, ", ")));
  }
  bitvec.resize(kReasonFlagsMaxSize, false);

  CrlDistributionPoints::Reasons reasons;
  if (bitvec[ReasonBitIndices::KEY_COMPROMISE]) {
    reasons.key_compromise = true;
  }
  if (bitvec[ReasonBitIndices::CA_COMPROMISE]) {
    reasons.ca_compromise = true;
  }
  if (bitvec[ReasonBitIndices::AFFILIATION_CHANGED]) {
    reasons.affiliation_changed = true;
  }
  if (bitvec[ReasonBitIndices::SUPERSEDED]) {
    reasons.superseded = true;
  }
  if (bitvec[ReasonBitIndices::CESSATION_OF_OPERATION]) {
    reasons.cessation_of_operation = true;
  }
  if (bitvec[ReasonBitIndices::CERTIFICATE_HOLD]) {
    reasons.certificate_hold = true;
  }
  if (bitvec[ReasonBitIndices::PRIVILEDGE_WITHDRAWN]) {
    reasons.priviledge_withdrawn = true;
  }
  if (bitvec[ReasonBitIndices::AA_COMPROMISE]) {
    reasons.aa_compromise = true;
  }
  return reasons;
}

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
        return Status(absl::StatusCode::kInternal, BsslLastErrorString());
      }

      if (EVP_PKEY_assign_EC_KEY(evp_key.get(), ec_key.release()) != 1) {
        return Status(absl::StatusCode::kInternal, BsslLastErrorString());
      }

      return std::move(evp_key);
    }
    case NID_rsassaPss:
    case NID_sha256WithRSAEncryption: {
      uint8_t const *public_key_data = public_key_der.data();

      // Create a public key from the input data. If |a| was set, the EC_KEY
      // object referenced by |a| would be freed and |a| would be updated to
      // point to the returned object.
      bssl::UniquePtr<RSA> rsa_key(d2i_RSA_PUBKEY(
          /*out=*/nullptr, &public_key_data, public_key_der.size()));
      if (!rsa_key) {
        return Status(absl::StatusCode::kInternal, BsslLastErrorString());
      }

      if (EVP_PKEY_assign_RSA(evp_key.get(), rsa_key.release()) != 1) {
        return Status(absl::StatusCode::kInternal, BsslLastErrorString());
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
          absl::StatusCode::kUnimplemented,
          absl::StrCat("Signature algorithm not supported: ", signature_name));
    }
  }
}

// Returns the DER-encoding of |evp_key|.
StatusOr<std::string> EvpPkeyToDer(const EVP_PKEY &evp_key) {
  bssl::UniquePtr<BIO> key_bio(BIO_new(BIO_s_mem()));
  if (i2d_PUBKEY_bio(key_bio.get(), const_cast<EVP_PKEY *>(&evp_key)) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  char *public_key_data = nullptr;
  int64_t public_key_length = BIO_get_mem_data(key_bio.get(), &public_key_data);
  if (public_key_length <= 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::string(public_key_data, public_key_length);
}

StatusOr<std::string> ToPemEncoding(X509 *x509) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_X509(bio.get(), x509)) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  char *data;
  long length = BIO_get_mem_data(bio.get(), &data);
  if (length <= 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return std::string(data, length);
}

StatusOr<std::string> ToDerEncoding(X509 *x509) {
  bssl::UniquePtr<BIO> x509_bio(BIO_new(BIO_s_mem()));
  if (i2d_X509_bio(x509_bio.get(), x509) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  char *data;
  long length = BIO_get_mem_data(x509_bio.get(), &data);
  if (length <= 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::string(data, length);
}

StatusOr<std::string> ToPemEncoding(X509_REQ *x509_req) {
  bssl::UniquePtr<BIO> x509_bio(BIO_new(BIO_s_mem()));
  if (PEM_write_bio_X509_REQ(x509_bio.get(), x509_req) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  char *data;
  long length = BIO_get_mem_data(x509_bio.get(), &data);
  if (length <= 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return std::string(data, length);
}

StatusOr<std::string> ToDerEncoding(X509_REQ *x509_req) {
  bssl::UniquePtr<BIO> x509_bio(BIO_new(BIO_s_mem()));
  if (i2d_X509_REQ_bio(x509_bio.get(), x509_req) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  char *data;
  long length = BIO_get_mem_data(x509_bio.get(), &data);
  if (length <= 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return std::string(data, length);
}

// Returns a std::vector<char> with the same contents as |str|. This is useful
// for obtaining a non-const char * based on a string. The returned vector ends
// with a null byte.
std::vector<char> ToCharVector(absl::string_view str) {
  std::vector<char> vec(str.begin(), str.end());
  vec.push_back('\0');
  return vec;
}

// Converts |asn1_time| to an absl::Time.
StatusOr<absl::Time> AbslTimeFromAsn1Time(const ASN1_TIME &asn1_time) {
  constexpr absl::Duration kOneDay = absl::Hours(24);

  static absl::once_flag once_init;
  static ASN1_TIME *unix_epoch;
  absl::call_once(once_init, [] {
    unix_epoch = ASN1_TIME_new();
    CHECK_NE(ASN1_TIME_set(unix_epoch, 0), nullptr) << BsslLastErrorString();
  });

  int num_days;
  int num_seconds;
  if (ASN1_TIME_diff(&num_days, &num_seconds, unix_epoch, &asn1_time) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  absl::Time time =
      absl::UnixEpoch() + num_days * kOneDay + absl::Seconds(num_seconds);
  if (time == absl::InfinitePast() || time == absl::InfiniteFuture()) {
    return Status(absl::StatusCode::kOutOfRange,
                  "Time is too large or too small");
  }
  return time;
}

// Converts |time| to an ASN1_TIME.
StatusOr<bssl::UniquePtr<ASN1_TIME>> Asn1TimeFromAbslTime(absl::Time time) {
  intmax_t unix_seconds = absl::ToUnixSeconds(time);

  if (unix_seconds < std::numeric_limits<time_t>::min() ||
      unix_seconds > std::numeric_limits<time_t>::max()) {
    return Status(absl::StatusCode::kOutOfRange,
                  "Time value cannot fit in a time_t");
  }

  bssl::UniquePtr<ASN1_TIME> asn1_time(
      ASN1_TIME_set(/*s=*/nullptr, absl::ToTimeT(time)));
  if (asn1_time == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  // GCC 4.9 requires this std::move() invocation.
  return std::move(asn1_time);
}

// Parses |x509_name| into an X509Name.
StatusOr<X509Name> ReadName(const X509_NAME &x509_name) {
  // Copy since |x509_name| is const. The const_cast<>() is safe because
  // X509_NAME_dup() does not modify its parameter.
  bssl::UniquePtr<X509_NAME> x509_name_copy(
      X509_NAME_dup(const_cast<X509_NAME *>(&x509_name)));

  int num_entries = X509_NAME_entry_count(x509_name_copy.get());
  X509Name name(num_entries);
  Asn1Value asn1;
  for (int i = 0; i < num_entries; ++i) {
    X509_NAME_ENTRY *entry = X509_NAME_get_entry(x509_name_copy.get(), i);
    ASYLO_ASSIGN_OR_RETURN(
        name[i].field,
        ObjectId::CreateFromBsslObject(*X509_NAME_ENTRY_get_object(entry)));

    unsigned char *value_utf8_unowned;
    int value_utf8_length = ASN1_STRING_to_UTF8(
        &value_utf8_unowned, X509_NAME_ENTRY_get_data(entry));
    if (value_utf8_length < 0) {
      return Status(absl::StatusCode::kInternal, BsslLastErrorString());
    }
    bssl::UniquePtr<unsigned char> value_utf8(value_utf8_unowned);
    name[i].value = std::string(
        reinterpret_cast<const char *>(value_utf8.get()), value_utf8_length);
  }
  return name;
}

// Writes |name| as an X509_NAME.
StatusOr<bssl::UniquePtr<X509_NAME>> WriteName(const X509Name &name) {
  bssl::UniquePtr<X509_NAME> x509_name(X509_NAME_new());
  for (const X509NameEntry &entry : name) {
    bssl::UniquePtr<ASN1_OBJECT> oid;
    ASYLO_ASSIGN_OR_RETURN(oid, entry.field.GetBsslObjectCopy());
    std::vector<char> entry_value = ToCharVector(entry.value);
    if (X509_NAME_add_entry_by_OBJ(
            x509_name.get(), oid.get(), MBSTRING_UTF8,
            reinterpret_cast<unsigned char *>(entry_value.data()),
            entry_value.size() - 1, /*loc=*/-1,
            /*set=*/0) != 1) {
      return Status(absl::StatusCode::kInternal, BsslLastErrorString());
    }
  }

  // GCC 4.9 requires this std::move() invocation.
  return std::move(x509_name);
}

// Adds |x509_extension| to |x509|.
Status AddSingleExtension(X509_EXTENSION *x509_extension, X509 *x509) {
  constexpr int kAddExtensionToEnd = -1;

  if (X509_add_ext(x509, x509_extension, /*loc=*/kAddExtensionToEnd) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

// Sets the X.509 version in |x509|.
Status SetVersion(X509Version version, X509 *x509) {
  if (X509_set_version(x509, static_cast<long>(version)) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

// Sets the PKCS 10 version in |x509_req|.
Status SetVersion(Pkcs10Version version, X509_REQ *x509_req) {
  if (X509_REQ_set_version(x509_req,
                           static_cast<long>(version)) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

// Sets the serial number in |x509|.
Status SetSerialNumber(const BIGNUM &serial_number, X509 *x509) {
  if (BN_is_negative(&serial_number)) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "X.509 certificate serial number must be positive");
  }

  Asn1Value serial_asn1_value;
  ASYLO_ASSIGN_OR_RETURN(serial_asn1_value,
                         Asn1Value::CreateInteger(serial_number));
  bssl::UniquePtr<ASN1_INTEGER> serial_asn1_integer;
  ASYLO_ASSIGN_OR_RETURN(serial_asn1_integer,
                         serial_asn1_value.GetBsslInteger());
  if (X509_set_serialNumber(x509, serial_asn1_integer.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

// Sets the issuer name in |x509|.
Status SetIssuerName(const X509Name &name, X509 *x509) {
  bssl::UniquePtr<X509_NAME> x509_name;
  ASYLO_ASSIGN_OR_RETURN(x509_name, WriteName(name));
  if (X509_set_issuer_name(x509, x509_name.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

// Sets the validity period in |x509|.
Status SetValidity(X509Validity validity, X509 *x509) {
  bssl::UniquePtr<ASN1_TIME> asn1_time;
  ASYLO_ASSIGN_OR_RETURN(asn1_time, Asn1TimeFromAbslTime(validity.not_before));
  if (X509_set_notBefore(x509, asn1_time.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  ASYLO_ASSIGN_OR_RETURN(asn1_time, Asn1TimeFromAbslTime(validity.not_after));
  if (X509_set_notAfter(x509, asn1_time.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

// Sets the subject name in |x509|.
Status SetSubjectName(const X509Name &name, X509 *x509) {
  bssl::UniquePtr<X509_NAME> x509_name;
  ASYLO_ASSIGN_OR_RETURN(x509_name, WriteName(name));
  if (X509_set_subject_name(x509, x509_name.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

// Sets the subject name in |x509_req|.
Status SetSubjectName(const X509Name &name, X509_REQ *x509_req) {
  bssl::UniquePtr<X509_NAME> x509_name;
  ASYLO_ASSIGN_OR_RETURN(x509_name, WriteName(name));
  if (X509_REQ_set_subject_name(x509_req, x509_name.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

// Sets the subject key in |x509|.
Status SetSubjectPublicKey(absl::string_view subject_key_der, X509 *x509) {
  const unsigned char *der_data =
      reinterpret_cast<const unsigned char *>(subject_key_der.data());
  bssl::UniquePtr<EVP_PKEY> evp_pkey(d2i_PUBKEY(
      /*out=*/nullptr, &der_data, subject_key_der.size()));
  if (evp_pkey == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  if (X509_set_pubkey(x509, evp_pkey.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

// Sets the subject key in |x509_req|.
Status SetSubjectPublicKey(absl::string_view subject_key_der,
                           X509_REQ *x509_req) {
  const unsigned char *der_data =
      reinterpret_cast<const unsigned char *>(subject_key_der.data());
  bssl::UniquePtr<EVP_PKEY> evp_pkey(d2i_PUBKEY(
      /*out=*/nullptr, &der_data, subject_key_der.size()));
  if (evp_pkey == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  if (X509_REQ_set_pubkey(x509_req, evp_pkey.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

// Sets the authority key identifier in |x509|.
Status SetAuthorityKeyId(ByteContainerView authority_key_id, X509 *x509) {
  bssl::UniquePtr<AUTHORITY_KEYID> bssl_key_id(AUTHORITY_KEYID_new());
  Asn1Value key_id_asn1;
  ASYLO_ASSIGN_OR_RETURN(key_id_asn1,
                         Asn1Value::CreateOctetString(authority_key_id));
  bssl::UniquePtr<ASN1_OCTET_STRING> key_id_octet_string;
  ASYLO_ASSIGN_OR_RETURN(key_id_octet_string, key_id_asn1.GetBsslOctetString());

  // Pass ownership to |bssl_key_id|.
  bssl_key_id->keyid = key_id_octet_string.release();

  bssl::UniquePtr<X509_EXTENSION> extension(X509V3_EXT_i2d(
      NID_authority_key_identifier, /*crit=*/0, bssl_key_id.get()));
  if (extension == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return AddSingleExtension(extension.get(), x509);
}

// Sets the subject key identifier in |x509| based on |method|.
Status SetSubjectKeyId(SubjectKeyIdMethod method, X509 *x509) {
  // For an explanation of the API that the code below is using, see
  // https://www.openssl.org/docs/manmaster/man5/x509v3_config.html or the
  // s2i_skey_id() function from v3_skey.c in BoringSSL.

  // Note: this string must match the corresponding one in v3_skey.c.
  constexpr char kUseSha1Hash[] = "hash";

  bssl::UniquePtr<X509_EXTENSION> extension;
  X509V3_CTX context;
  switch (method) {
    case SubjectKeyIdMethod::kSubjectPublicKeySha1:
      X509V3_set_ctx(&context, /*issuer=*/nullptr, /*subject=*/x509,
                     /*req=*/nullptr, /*crl=*/nullptr, /*flags=*/0);
      extension.reset(X509V3_EXT_nconf_nid(
          /*conf=*/nullptr, /*ctx=*/&context, NID_subject_key_identifier,
          ToCharVector(kUseSha1Hash).data()));
      if (extension == nullptr) {
        return Status(absl::StatusCode::kInternal, BsslLastErrorString());
      }
      break;
  }

  return AddSingleExtension(extension.get(), x509);
}

// Sets the key usage in |x509|.
Status SetKeyUsage(KeyUsageInformation key_usage, X509 *x509) {
  // For an explanation of the API that the code below is using, see
  // https://www.openssl.org/docs/manmaster/man5/x509v3_config.html or the
  // s2i_skey_id() function from v3_bitst.c in BoringSSL.

  // Note: these strings must match the corresponding ones in v3_bitst.c.
  constexpr char kCertificateSigning[] = "keyCertSign";
  constexpr char kCrlSigning[] = "cRLSign";
  constexpr char kDigitalSignature[] = "digitalSignature";

  std::vector<const char *> usage_strings;
  if (key_usage.certificate_signing) {
    usage_strings.push_back(kCertificateSigning);
  }
  if (key_usage.crl_signing) {
    usage_strings.push_back(kCrlSigning);
  }
  if (key_usage.digital_signature) {
    usage_strings.push_back(kDigitalSignature);
  }

  bssl::UniquePtr<X509_EXTENSION> extension(X509V3_EXT_nconf_nid(
      /*conf=*/nullptr, /*ctx=*/nullptr, NID_key_usage,
      ToCharVector(
          absl::StrCat("critical, ", absl::StrJoin(usage_strings, ",")))
          .data()));
  if (extension == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return AddSingleExtension(extension.get(), x509);
}

// Sets the basic constraints in |x509|.
Status SetBasicConstraints(BasicConstraints basic_constraints, X509 *x509) {
  bssl::UniquePtr<BASIC_CONSTRAINTS> bssl_constraints(BASIC_CONSTRAINTS_new());
  // DER encodes TRUE as 0xff. See X.690 (08/2015) section 11.1.
  bssl_constraints->ca = basic_constraints.is_ca ? 0xff : 0;
  if (basic_constraints.pathlen.has_value()) {
    Asn1Value integer;
    ASYLO_ASSIGN_OR_RETURN(integer, Asn1Value::CreateIntegerFromInt(
                                        basic_constraints.pathlen.value()));
    bssl::UniquePtr<ASN1_INTEGER> bssl_integer;
    ASYLO_ASSIGN_OR_RETURN(bssl_integer, integer.GetBsslInteger());
    bssl_constraints->pathlen = bssl_integer.release();
  }

  bssl::UniquePtr<X509_EXTENSION> extension(X509V3_EXT_i2d(
      NID_basic_constraints, /*crit=*/1, bssl_constraints.get()));
  if (extension == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return AddSingleExtension(extension.get(), x509);
}

// Sets the CRL distribution points in |x509|.
Status SetCrlDistributionPoints(
    const CrlDistributionPoints &crl_distribution_points, X509 *x509) {
  bssl::UniquePtr<ASN1_IA5STRING> uri(ASN1_IA5STRING_new());
  if (ASN1_STRING_set(uri.get(), crl_distribution_points.uri.data(),
                      crl_distribution_points.uri.size()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  bssl::UniquePtr<GENERAL_NAME> general_name(GENERAL_NAME_new());
  GENERAL_NAME_set0_value(general_name.get(), GEN_URI, uri.release());

  bssl::UniquePtr<DIST_POINT> dist_point(DIST_POINT_new());
  dist_point->distpoint = DIST_POINT_NAME_new();
  // See v3_crld.c for an illustration that this |type| value corresponds to the
  // |fullname| union field.
  dist_point->distpoint->type = 0;
  dist_point->distpoint->name.fullname = GENERAL_NAMES_new();
  if (sk_GENERAL_NAME_push(dist_point->distpoint->name.fullname,
                           general_name.release()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  if (crl_distribution_points.reasons.has_value()) {
    std::vector<bool> reasons_bitvec;
    int reasons_flags;
    std::tie(reasons_bitvec, reasons_flags) =
        ReasonsToBitvecAndFlags(crl_distribution_points.reasons.value());
    Asn1Value reasons_asn1;
    ASYLO_ASSIGN_OR_RETURN(reasons_asn1,
                           Asn1Value::CreateBitString(reasons_bitvec));
    bssl::UniquePtr<ASN1_BIT_STRING> bssl_reasons;
    ASYLO_ASSIGN_OR_RETURN(bssl_reasons, reasons_asn1.GetBsslBitString());
    dist_point->reasons = bssl_reasons.release();
    dist_point->dp_reasons = reasons_flags;
  }

  bssl::UniquePtr<CRL_DIST_POINTS> bssl_crl_dist_points(CRL_DIST_POINTS_new());
  if (sk_DIST_POINT_push(bssl_crl_dist_points.get(), dist_point.release()) !=
      1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  bssl::UniquePtr<X509_EXTENSION> extension(X509V3_EXT_i2d(
      NID_crl_distribution_points, /*crit=*/0, bssl_crl_dist_points.get()));
  if (extension == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return AddSingleExtension(extension.get(), x509);
}

// Adds the extensions in |extensions| to |x509|.
Status AddExtensions(absl::Span<const X509Extension> extensions, X509 *x509) {
  for (const X509Extension &extension : extensions) {
    std::vector<uint8_t> data_der;
    ASYLO_ASSIGN_OR_RETURN(data_der, extension.value.SerializeToDer());
    Asn1Value data;
    ASYLO_ASSIGN_OR_RETURN(data, Asn1Value::CreateOctetString(data_der));
    bssl::UniquePtr<ASN1_OCTET_STRING> data_bssl;
    ASYLO_ASSIGN_OR_RETURN(data_bssl, data.GetBsslOctetString());

    bssl::UniquePtr<X509_EXTENSION> x509_extension(X509_EXTENSION_create_by_OBJ(
        /*ex=*/nullptr, &extension.oid.GetBsslObject(), extension.is_critical,
        data_bssl.get()));
    if (x509_extension == nullptr) {
      return Status(absl::StatusCode::kInternal, BsslLastErrorString());
    }
    ASYLO_RETURN_IF_ERROR(AddSingleExtension(x509_extension.get(), x509));
  }
  return absl::OkStatus();
}

}  // namespace

bool operator==(const X509NameEntry &lhs, const X509NameEntry &rhs) {
  return lhs.field == rhs.field && lhs.value == rhs.value;
}

bool operator!=(const X509NameEntry &lhs, const X509NameEntry &rhs) {
  return !(lhs == rhs);
}

std::ostream &operator<<(std::ostream &out, const X509NameEntry &entry) {
  return out << entry.field << "=" << entry.value;
}

StatusOr<std::unique_ptr<X509Certificate>> X509CertificateBuilder::SignAndBuild(
    const X509Signer &issuer_key) const {
  if (serial_number == nullptr) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot SignAndBuild() X.509 certificate without a serial number");
  }
  if (!issuer.has_value()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Cannot SignAndBuild() X.509 certificate without an issuer");
  }
  if (!validity.has_value()) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot SignAndBuild() X.509 certificate without a validity period");
  }
  if (!subject.has_value()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Cannot SignAndBuild() X.509 certificate without a subject");
  }
  if (!subject_public_key_der.has_value()) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot SignAndBuild() X.509 certificate without a subject key");
  }

  bssl::UniquePtr<X509> x509(X509_new());
  ASYLO_RETURN_IF_ERROR(WithContext(SetVersion(version, x509.get()),
                                    "Failed to set X.509 version: "));
  ASYLO_RETURN_IF_ERROR(
      WithContext(SetSerialNumber(*serial_number, x509.get()),
                  "Failed to set certificate serial number: "));
  ASYLO_RETURN_IF_ERROR(WithContext(SetIssuerName(issuer.value(), x509.get()),
                                    "Failed to set certificate issuer name: "));
  ASYLO_RETURN_IF_ERROR(
      WithContext(SetValidity(validity.value(), x509.get()),
                  "Failed to set certificate validity period: "));
  ASYLO_RETURN_IF_ERROR(
      WithContext(SetSubjectName(subject.value(), x509.get()),
                  "Failed to set certificate subject name: "));
  ASYLO_RETURN_IF_ERROR(WithContext(
      SetSubjectPublicKey(subject_public_key_der.value(), x509.get()),
      "Failed to set certificate subject public key: "));
  if (authority_key_identifier.has_value()) {
    ASYLO_RETURN_IF_ERROR(WithContext(
        SetAuthorityKeyId(authority_key_identifier.value(), x509.get()),
        "Failed to set authority key identifier: "));
  }
  if (subject_key_identifier_method.has_value()) {
    ASYLO_RETURN_IF_ERROR(WithContext(
        SetSubjectKeyId(subject_key_identifier_method.value(), x509.get()),
        "Failed to set subject key identifier: "));
  }
  if (key_usage.has_value()) {
    ASYLO_RETURN_IF_ERROR(
        WithContext(SetKeyUsage(key_usage.value(), x509.get()),
                    "Failed to set certificate key usage: "));
  }
  if (basic_constraints.has_value()) {
    ASYLO_RETURN_IF_ERROR(
        WithContext(SetBasicConstraints(basic_constraints.value(), x509.get()),
                    "Failed to set certificate basic constraints: "));
  }
  if (crl_distribution_points.has_value()) {
    ASYLO_RETURN_IF_ERROR(WithContext(
        SetCrlDistributionPoints(crl_distribution_points.value(), x509.get()),
        "Failed to set certificate CRL distribution points: "));
  }
  ASYLO_RETURN_IF_ERROR(WithContext(
      AddExtensions(absl::MakeConstSpan(other_extensions), x509.get()),
      "Failed to add certificate extensions: "));
  ASYLO_RETURN_IF_ERROR(WithContext(issuer_key.SignX509(x509.get()),
                                    "Failed to sign certificate: "));
  return absl::WrapUnique(new X509Certificate(std::move(x509)));
}

StatusOr<std::string> X509CsrBuilder::SignAndBuild() const {
  if (!subject.has_value()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Cannot SignAndBuild without a subject");
  }

  if (key == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Cannot SignAndBuild without a key");
  }

  bssl::UniquePtr<X509_REQ> x509_req(X509_REQ_new());
  if (x509_req == nullptr) {
    return Status(absl::StatusCode::kInternal, "Error allocating X509_REQ");
  }

  ASYLO_RETURN_IF_ERROR(SetVersion(version, x509_req.get()));

  ASYLO_RETURN_IF_ERROR(SetSubjectName(subject.value(), x509_req.get()));

  std::string public_key_der;
  ASYLO_ASSIGN_OR_RETURN(public_key_der, key->SerializePublicKeyToDer());

  ASYLO_RETURN_IF_ERROR(SetSubjectPublicKey(public_key_der, x509_req.get()));

  ASYLO_RETURN_IF_ERROR(
      WithContext(key->SignX509Req(x509_req.get()), "Failed to sign CSR: "));

  return ToPemEncoding(x509_req.get());
}

StatusOr<std::unique_ptr<X509Certificate>> X509Certificate::Create(
    const Certificate &certificate) {
  switch (certificate.format()) {
    case Certificate::X509_PEM:
      return CreateFromPem(certificate.data());
    case Certificate::X509_DER:
      return CreateFromDer(certificate.data());
    default:
      return Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Transformation to X509 is not supported for: ",
                       ProtoEnumValueName(certificate.format())));
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
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
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
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::WrapUnique<X509Certificate>(
      new X509Certificate(std::move(x509)));
}

bool X509Certificate::operator==(const CertificateInterface &other) const {
  X509Certificate const *other_cert =
      dynamic_cast<X509Certificate const *>(&other);
  if (other_cert == nullptr) {
    return false;
  }

  return X509_cmp(x509_.get(), other_cert->x509_.get()) == 0;
}

StatusOr<Certificate> X509Certificate::ToCertificateProto(
    Certificate::CertificateFormat encoding) const {
  Certificate cert;
  cert.set_format(encoding);
  switch (encoding) {
    case Certificate::X509_DER:
      ASYLO_ASSIGN_OR_RETURN(*cert.mutable_data(), ToDerEncoding(x509_.get()));
      return cert;
    case Certificate::X509_PEM:
      ASYLO_ASSIGN_OR_RETURN(*cert.mutable_data(), ToPemEncoding(x509_.get()));
      return cert;
    case Certificate::SGX_ATTESTATION_KEY_CERTIFICATE:
      return Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrFormat("Certificate format (%s) is not a valid encoding for "
                          "an X.509 certificate",
                          Certificate_CertificateFormat_Name(encoding)));
    case Certificate::UNKNOWN:
      break;
  }
  return Status(absl::StatusCode::kInvalidArgument,
                absl::StrFormat("Certificate format (%s) unknown",
                                ProtoEnumValueName(encoding)));
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
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Transformation to X509_REQ not suported for: ",
                       ProtoEnumValueName(csr.format())));
  }
  if (req == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return std::move(req);
}

StatusOr<CertificateSigningRequest> X509ReqToDerCertificateSigningRequest(
    const X509_REQ &x509_req) {
  std::string der;
  ASYLO_ASSIGN_OR_RETURN(der, ToDerEncoding(const_cast<X509_REQ *>(&x509_req)));

  CertificateSigningRequest csr;
  csr.set_format(CertificateSigningRequest::PKCS10_DER);
  csr.set_data(der);
  return csr;
}

StatusOr<std::string> ExtractPkcs10SubjectKeyDer(
    const CertificateSigningRequest &csr) {
  bssl::UniquePtr<X509_REQ> x509_req;
  ASYLO_ASSIGN_OR_RETURN(x509_req, CertificateSigningRequestToX509Req(csr));

  bssl::UniquePtr<EVP_PKEY> public_key(X509_REQ_get_pubkey(x509_req.get()));
  if (public_key == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
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
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  if (config.issuer_ca) {
    absl::optional<bool> issuer_is_ca = issuer_certificate.IsCa();
    if (issuer_is_ca.has_value() && !issuer_is_ca.value()) {
      return Status(absl::StatusCode::kUnauthenticated,
                    "Issuer had a CA extension value of false");
    }
  }

  if (config.issuer_key_usage) {
    absl::optional<KeyUsageInformation> key_usage =
        issuer_certificate.KeyUsage();
    if (key_usage.has_value() && !key_usage.value().certificate_signing) {
      return Status(
          absl::StatusCode::kUnauthenticated,
          "Issuer's key usage extension did not include certificate signing");
    }
  }

  if (config.subject_validity_period.has_value()) {
    bool within_period;
    ASYLO_ASSIGN_OR_RETURN(
        within_period,
        WithinValidityPeriod(config.subject_validity_period.value()));
    if (!within_period) {
      return Status(absl::StatusCode::kUnauthenticated,
                    "Subject certificate is not valid at this time.");
    }
  }

  return absl::OkStatus();
}

StatusOr<std::string> X509Certificate::SubjectKeyDer() const {
  bssl::UniquePtr<EVP_PKEY> evp_key(X509_get_pubkey(x509_.get()));
  if (evp_key == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return EvpPkeyToDer(*evp_key);
}

absl::optional<std::string> X509Certificate::SubjectName() const {
  bssl::UniquePtr<BIO> subject_name_bio(BIO_new(BIO_s_mem()));
  if (!X509_NAME_print_ex(subject_name_bio.get(),
                          X509_get_subject_name(x509_.get()), 0,
                          XN_FLAG_RFC2253)) {
    // This should never happen. OpenSSL doesn't even check for errors from this
    // function in many cases.
    LOG(ERROR) << BsslLastErrorString();
    return absl::nullopt;
  }

  char *subject_name_string = nullptr;
  int64_t subject_name_length =
      BIO_get_mem_data(subject_name_bio.get(), &subject_name_string);
  if (subject_name_length <= 0 || subject_name_string == nullptr) {
    // This should never happen. The BIO is created above, and we KNOW it's a
    // mem bio, so getting the pointer should not fail.
    LOG(ERROR) << BsslLastErrorString();
    return absl::nullopt;
  }
  return std::string(subject_name_string, subject_name_length);
}

absl::optional<bool> X509Certificate::IsCa() const {
  // Version 3 of X.509 introduces standard extensions.
  if (X509_get_version(x509_.get()) !=
      static_cast<long>(X509Version::kVersion3)) {
    return absl::nullopt;
  }
  return X509_check_ca(x509_.get()) != 0;
}

absl::optional<int64_t> X509Certificate::CertPathLength() const {
  auto basic_constraints_result = GetBasicConstraints();
  if (!basic_constraints_result.ok()) {
    LOG(ERROR) << basic_constraints_result.status();
    return absl::nullopt;
  }
  absl::optional<BasicConstraints> basic_constraints =
      basic_constraints_result.value();
  return basic_constraints.has_value() ? basic_constraints->pathlen
                                       : absl::nullopt;
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

X509Version X509Certificate::GetVersion() const {
  return static_cast<X509Version>(X509_get_version(x509_.get()));
}

StatusOr<bssl::UniquePtr<BIGNUM>> X509Certificate::GetSerialNumber() const {
  Asn1Value serial_asn1_value;
  ASYLO_RETURN_IF_ERROR(
      serial_asn1_value.SetBsslInteger(*X509_get_serialNumber(x509_.get())));
  return serial_asn1_value.GetInteger();
}

StatusOr<bool> X509Certificate::WithinValidityPeriod(
    const absl::Time &time) const {
  X509Validity subject_validity_period;
  ASYLO_ASSIGN_OR_RETURN(subject_validity_period, GetValidity());
  return subject_validity_period.not_before <= time &&
         subject_validity_period.not_after >= time;
}

StatusOr<X509Name> X509Certificate::GetIssuerName() const {
  return ReadName(*X509_get_issuer_name(x509_.get()));
}

StatusOr<X509Validity> X509Certificate::GetValidity() const {
  X509Validity validity;
  ASYLO_ASSIGN_OR_RETURN(
      validity.not_before,
      AbslTimeFromAsn1Time(*X509_get0_notBefore(x509_.get())));
  ASYLO_ASSIGN_OR_RETURN(
      validity.not_after,
      AbslTimeFromAsn1Time(*X509_get0_notAfter(x509_.get())));
  return validity;
}

StatusOr<X509Name> X509Certificate::GetSubjectName() const {
  return ReadName(*X509_get_subject_name(x509_.get()));
}

StatusOr<absl::optional<std::vector<uint8_t>>>
X509Certificate::GetAuthorityKeyIdentifier() const {
  bssl::UniquePtr<AUTHORITY_KEYID> bssl_key_id;
  ASYLO_ASSIGN_OR_RETURN(bssl_key_id, GetExtensionAsType<AUTHORITY_KEYID>(
                                          NID_authority_key_identifier));
  if (bssl_key_id == nullptr) {
    return absl::nullopt;
  }

  Asn1Value asn1;
  ASYLO_ASSIGN_OR_RETURN(
      asn1, Asn1Value::CreateOctetStringFromBssl(*bssl_key_id->keyid));
  return asn1.GetOctetString();
}

StatusOr<absl::optional<std::vector<uint8_t>>>
X509Certificate::GetSubjectKeyIdentifier() const {
  bssl::UniquePtr<ASN1_OCTET_STRING> bssl_key_id;
  ASYLO_ASSIGN_OR_RETURN(bssl_key_id, GetExtensionAsType<ASN1_OCTET_STRING>(
                                          NID_subject_key_identifier));
  if (bssl_key_id == nullptr) {
    return absl::nullopt;
  }

  Asn1Value asn1;
  ASYLO_ASSIGN_OR_RETURN(asn1,
                         Asn1Value::CreateOctetStringFromBssl(*bssl_key_id));
  return asn1.GetOctetString();
}

StatusOr<absl::optional<BasicConstraints>>
X509Certificate::GetBasicConstraints() const {
  bssl::UniquePtr<BASIC_CONSTRAINTS> bssl_constraints;
  ASYLO_ASSIGN_OR_RETURN(
      bssl_constraints,
      GetExtensionAsType<BASIC_CONSTRAINTS>(NID_basic_constraints));
  if (bssl_constraints == nullptr) {
    return absl::nullopt;
  }

  BasicConstraints basic_constraints;
  basic_constraints.is_ca = bssl_constraints->ca;
  if (bssl_constraints->pathlen != nullptr) {
    Asn1Value pathlen;
    ASYLO_ASSIGN_OR_RETURN(
        pathlen, Asn1Value::CreateIntegerFromBssl(*bssl_constraints->pathlen));
    ASYLO_ASSIGN_OR_RETURN(basic_constraints.pathlen,
                           pathlen.GetIntegerAsInt<int64_t>());
  }
  return basic_constraints;
}

StatusOr<absl::optional<CrlDistributionPoints>>
X509Certificate::GetCrlDistributionPoints() const {
  bssl::UniquePtr<CRL_DIST_POINTS> bssl_crl_dist_points;
  ASYLO_ASSIGN_OR_RETURN(
      bssl_crl_dist_points,
      GetExtensionAsType<CRL_DIST_POINTS>(NID_crl_distribution_points));
  if (bssl_crl_dist_points == nullptr) {
    return absl::nullopt;
  }

  CrlDistributionPoints crl_distribution_points;
  if (sk_DIST_POINT_num(bssl_crl_dist_points.get()) != 1) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot represent a CrlDistributionPoints that does not have exactly "
        "one DistributionPoint");
  }
  DIST_POINT *bssl_dist_point =
      sk_DIST_POINT_value(bssl_crl_dist_points.get(), 0);
  if (bssl_dist_point->distpoint == nullptr) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot represent a DistributionPoint without a distributionPoint");
  }
  if (bssl_dist_point->CRLissuer != nullptr) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Cannot represent a DistributionPoint with a cRLIssuer");
  }
  // See v3_crld.c for an illustration that this |type| value corresponds to the
  // |fullname| union field.
  if (bssl_dist_point->distpoint->type != 0) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Cannot represent a DistributionPointName of the "
                  "nameRelativeToCRLIssuer variant");
  }
  if (sk_GENERAL_NAME_num(bssl_dist_point->distpoint->name.fullname) != 1) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot represent a GeneralNames that does not have exactly one "
        "GeneralName");
  }
  GENERAL_NAME *bssl_general_name =
      sk_GENERAL_NAME_value(bssl_dist_point->distpoint->name.fullname, 0);
  if (bssl_general_name->type != GEN_URI) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Cannot represent a GeneralName that is not of the "
                  "uniformResourceIdentifier variant");
  }
  unsigned char *uri_unowned;
  int uri_length = ASN1_STRING_to_UTF8(
      &uri_unowned, bssl_general_name->d.uniformResourceIdentifier);
  if (uri_length < 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  bssl::UniquePtr<unsigned char> uri(uri_unowned);
  crl_distribution_points.uri =
      std::string(reinterpret_cast<char *>(uri.get()), uri_length);

  if (bssl_dist_point->reasons != nullptr) {
    Asn1Value reasons_asn1;
    ASYLO_ASSIGN_OR_RETURN(reasons_asn1, Asn1Value::CreateBitStringFromBssl(
                                             *bssl_dist_point->reasons));
    std::vector<bool> reasons_bitvec;
    ASYLO_ASSIGN_OR_RETURN(reasons_bitvec, reasons_asn1.GetBitString());
    crl_distribution_points.reasons.emplace();
    ASYLO_ASSIGN_OR_RETURN(crl_distribution_points.reasons.value(),
                           BitvecToReasons(reasons_bitvec));
  }

  return crl_distribution_points;
}

StatusOr<std::vector<X509Extension>> X509Certificate::GetOtherExtensions()
    const {
  int extension_count = X509_get_ext_count(x509_.get());
  std::vector<X509Extension> extensions;
  for (int i = 0; i < extension_count; ++i) {
    X509_EXTENSION *bssl_extension = X509_get_ext(x509_.get(), i);
    if (bssl_extension == nullptr) {
      return Status(absl::StatusCode::kInternal, BsslLastErrorString());
    }
    int nid = OBJ_obj2nid(X509_EXTENSION_get_object(bssl_extension));
    if (nid == NID_authority_key_identifier ||
        nid == NID_subject_key_identifier || nid == NID_key_usage ||
        nid == NID_basic_constraints || nid == NID_crl_distribution_points) {
      continue;
    }

    X509Extension extension;
    ASYLO_ASSIGN_OR_RETURN(extension.oid,
                           ObjectId::CreateFromBsslObject(
                               *X509_EXTENSION_get_object(bssl_extension)));
    extension.is_critical = X509_EXTENSION_get_critical(bssl_extension);
    Asn1Value data;
    ASYLO_ASSIGN_OR_RETURN(data, Asn1Value::CreateOctetStringFromBssl(
                                     *X509_EXTENSION_get_data(bssl_extension)));
    std::vector<uint8_t> der;
    ASYLO_ASSIGN_OR_RETURN(der, data.GetOctetString());
    ASYLO_ASSIGN_OR_RETURN(extension.value, Asn1Value::CreateFromDer(der));
    extensions.push_back(extension);
  }
  return extensions;
}

X509Certificate::X509Certificate(bssl::UniquePtr<X509> x509)
    : x509_(std::move(x509)) {}

StatusOr<X509_EXTENSION *> X509Certificate::GetExtensionByNid(int nid) const {
  int index = X509_get_ext_by_NID(x509_.get(), nid, /*lastpos=*/-1);
  if (index == -1) {
    return nullptr;
  }
  X509_EXTENSION *extension = X509_get_ext(x509_.get(), index);
  if (extension == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return extension;
}

}  // namespace asylo
