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
#include <openssl/x509v3.h>

#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/asn1.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/x509_signer.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

class X509Certificate;

// For more information about the structures below, see RFC 5280
// (https://tools.ietf.org/html/rfc5280).

// The versions of the X.509 standard. The equivalent integer values are equal
// to the corresponding version integer values from the X.509 standard.
enum class X509Version {
  // Versions 1 and 2 are not supported.
  kVersion3 = 2,
};

// The versions of the PKCS 10 specification.
enum class Pkcs10Version {
  kVersion1 = 0,
};

// Represents an entry in an X.509 Name. The |value| field is UTF-8 encoded but
// will typically be an ASCII string.
struct X509NameEntry {
  ObjectId field;
  std::string value;
};

bool operator==(const X509NameEntry &lhs, const X509NameEntry &rhs);
bool operator!=(const X509NameEntry &lhs, const X509NameEntry &rhs);
std::ostream &operator<<(std::ostream &out, const X509NameEntry &entry);

// Represents an X.509 Name structure.
using X509Name = std::vector<X509NameEntry>;

// Represents an X.509 Validity period. Note that times in certificates only
// have second precision.
struct X509Validity {
  absl::Time not_before;
  absl::Time not_after;
};

// Represents a method for creating an X.509v3 Subject Key Identifier extension.
enum class SubjectKeyIdMethod {
  // The Subject Key Identifier should be the SHA-1 hash of the subject public
  // key.
  kSubjectPublicKeySha1,
};

// Represents an X.509v3 BasicConstraints extension.
struct BasicConstraints {
  bool is_ca;
  absl::optional<int64_t> pathlen;
};

// Represents an X.509v3 CRLDistributionsPoints extension. Currently,
// CrlDistributionPoints only supports having one DistributionPoint.
struct CrlDistributionPoints {
  // The types of revocations a CRL distribution point can make. From RFC 5280.
  struct Reasons {
    bool key_compromise = false;
    bool ca_compromise = false;
    bool affiliation_changed = false;
    bool superseded = false;
    bool cessation_of_operation = false;
    bool certificate_hold = false;
    bool priviledge_withdrawn = false;
    bool aa_compromise = false;
  };

  // The URI of the CRL distribution point. This will be encoded in the
  // uniformResourceIdentifier variant of the fullName field of the
  // distributionPoint field of the first (and only) distribution point in the
  // sequence.
  std::string uri;

  // The reasons field of the distribution point.
  absl::optional<Reasons> reasons;
};

// Represents an X.509 Extension.
struct X509Extension {
  ObjectId oid;
  bool is_critical = false;  // Default to false in accordance with RFC2459.
  Asn1Value value;
};

// Represents the data needed to create an X.509 certificate.
//
// Some of the absl::optional<...> fields in X509CertificateBuilder are in fact
// required, and SignAndBuild() will fail if they are absent. This is to prevent
// users from forgetting to set them.
//
// Note that the SignAndBuild() method does not enforce that the data in the
// X509CertificateBuilder represents a fully RFC 5280-compliant certificate. It
// is the responsibility of the user of X509CertificateBuilder to ensure that
// they comply with RFC 5280.
struct X509CertificateBuilder {
  // The X.509 version to use.
  X509Version version = X509Version::kVersion3;

  // The certificate's serial number. Required (i.e. must be non-null).
  bssl::UniquePtr<BIGNUM> serial_number;

  // The Name structure corresponding to the certificate's issuer. Required.
  absl::optional<X509Name> issuer;

  // The validity period of the certificate. Required.
  absl::optional<X509Validity> validity;

  // The Name structure corresponding to the certificate's subject. Required.
  absl::optional<X509Name> subject;

  // The subject public key of the certificate in DER form. Required.
  absl::optional<std::string> subject_public_key_der;

  // The authority key identifier of the certificate. Should be equal to either
  // the subject key identifier of the issuer or the combination of the issuer's
  // issuer Name and the issuer's serial number. Optional.
  absl::optional<std::vector<uint8_t>> authority_key_identifier;

  // How the subject key identifier for the certificate should be created.
  // Optional; if absent, no subject key identifier is created.
  absl::optional<SubjectKeyIdMethod> subject_key_identifier_method;

  // The key usage information for the certificate. Optional.
  absl::optional<KeyUsageInformation> key_usage;

  // The basic constraints imposed on the certificate's subject key's usage.
  // Optional.
  absl::optional<BasicConstraints> basic_constraints;

  // The CRL distribution points that should be used to check the revocation
  // status of this certificate. Optional.
  absl::optional<CrlDistributionPoints> crl_distribution_points;

  // Custom X.509 extensions and basic extensions not covered by other members.
  // Optional (i.e. may be empty).
  std::vector<X509Extension> other_extensions;

  // Builds an X.509 certificate using the data in this builder, signs the
  // certificate with |issuer_key|, and returns the certificate as an
  // X509Certificate.
  StatusOr<std::unique_ptr<X509Certificate>> SignAndBuild(
      const X509Signer &issuer_key) const;
};

// Represents the data needed to create an X.509 certificate signing request.
//
// Some of the absl::optional<...> fields in X509CsrBuilder are in fact
// required, and SignAndBuild() will fail if they are absent. This is to prevent
// users from forgetting to set them.
struct X509CsrBuilder {
  // The X.509 version to use.
  Pkcs10Version version = Pkcs10Version::kVersion1;

  // The Name structure corresponding to the certificate's subject. Required.
  absl::optional<X509Name> subject;

  // The key to certify. Required.
  std::unique_ptr<asylo::X509Signer> key;

  // Builds an X.509 CSR using the data in this builder, signs the
  // certificate using |key|, and returns the certificate as a PEM-encoded
  // PKCS 10 CSR.
  StatusOr<std::string> SignAndBuild() const;
};

// An implementation of CertificateInterface that can parse and verify
// X.509 certificates from PEM or DER encodings.
class X509Certificate : public CertificateInterface {
 public:
  // Creates and returns an X509Certificate with the given |certificate| as
  // data. Returns a non-OK Status if the certificate could not be transformed
  // into an X509Certificate.
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

  // From CertificateInterface.

  // Checks that the DER-encoded versions of this object and |other| are
  // equal. Returns false if the signatures are not equal, even if the
  // certificate data and signing key used to generate the signature are equal.
  bool operator==(const CertificateInterface &other) const override;

  // Based on |config|, checks if |issuer_certificate| is a CA certificate with
  // key usage for certificate signing. It is not an authentication failure if
  // either of these extensions are not set.
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

  // Returns this certificate's X.509 version.
  X509Version GetVersion() const;

  // Returns this certificate's serial number.
  StatusOr<bssl::UniquePtr<BIGNUM>> GetSerialNumber() const;

  // Returns the Name structure corresponding to this certificate's issuer.
  StatusOr<X509Name> GetIssuerName() const;

  // Returns the validity period of this certificate.
  StatusOr<X509Validity> GetValidity() const;

  // Returns the Name structure corresponding to this certificate's subject.
  StatusOr<X509Name> GetSubjectName() const;

  // Returns the authority key identifier for this certificate, or absl::nullopt
  // if it doesn't have one.
  StatusOr<absl::optional<std::vector<uint8_t>>> GetAuthorityKeyIdentifier()
      const;

  // Returns the subject key identifier for this certificate, or absl::nullopt
  // if it doesn't have one.
  StatusOr<absl::optional<std::vector<uint8_t>>> GetSubjectKeyIdentifier()
      const;

  // Returns the basic constraints imposed on this certificate's subject key, or
  // absl::nullopt if the certificate does not have a BasicConstraints
  // extension.
  StatusOr<absl::optional<BasicConstraints>> GetBasicConstraints() const;

  // Returns the distribution points for CRLs that may contain this certificate,
  // or absl::nullopt if the certificate does not have a CrlDistributionPoints
  // extension.
  StatusOr<absl::optional<CrlDistributionPoints>> GetCrlDistributionPoints()
      const;

  // Returns all of this certificate's extensions except the ones that can be
  // extracted by other methods of X509Certificate.
  StatusOr<std::vector<X509Extension>> GetOtherExtensions() const;

 private:
  friend struct X509CertificateBuilder;

  explicit X509Certificate(bssl::UniquePtr<X509> x509);

  // Returns the extension with NID |nid|, interpreted as the given type, or
  // nullptr if no such extension exists.
  template <typename X509v3ObjectT>
  StatusOr<bssl::UniquePtr<X509v3ObjectT>> GetExtensionAsType(int nid) const {
    X509_EXTENSION *extension;
    ASYLO_ASSIGN_OR_RETURN(extension, GetExtensionByNid(nid));
    if (extension == nullptr) {
      return nullptr;
    }
    bssl::UniquePtr<X509v3ObjectT> bssl_object(
        static_cast<X509v3ObjectT *>(X509V3_EXT_d2i(extension)));
    if (bssl_object == nullptr) {
      return Status(absl::StatusCode::kInternal, BsslLastErrorString());
    }

    // GCC requires this std::move() invocation.
    return std::move(bssl_object);
  }

  // Returns an internal pointer to the extension in |x509_| with NID |nid|, or
  // nullptr if |x509_| contains no such extension.
  StatusOr<X509_EXTENSION *> GetExtensionByNid(int nid) const;

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
