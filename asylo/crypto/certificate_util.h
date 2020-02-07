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

#ifndef ASYLO_CRYPTO_CERTIFICATE_UTIL_H_
#define ASYLO_CRYPTO_CERTIFICATE_UTIL_H_

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/types/span.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// A map from a CertificateFormat to the factory function to use when creating
// CertificateInterface objects.
using CertificateFactoryMap = absl::flat_hash_map<
    Certificate::CertificateFormat,
    std::function<StatusOr<std::unique_ptr<CertificateInterface>>(
        Certificate)>>;

using CertificateInterfaceVector =
    std::vector<std::unique_ptr<CertificateInterface>>;

using CertificateInterfaceSpan =
    absl::Span<const std::unique_ptr<CertificateInterface>>;

// Validates a CertificateSigningRequest message. Returns an OK status if and
// only if the message is valid.
//
// This function does NOT verify the contained CSR. It only checks that |csr|'s
// |format| and |data| fields are set and its |format| is not UNKNOWN.
Status ValidateCertificateSigningRequest(const CertificateSigningRequest &csr);

// Validates a Certificate message. Returns an OK status if and only if the
// message is valid.
//
// This function does NOT verify the contained certificate. It only checks that
// |certificate|'s |format| and |data| fields are set and its |format| is not
// UNKNOWN.
Status ValidateCertificate(const Certificate &certificate);

// Validates a Certificate message and the data contained within it. Returns an
// OK status if and only if the message is valid and the data parses
// successfully.
Status FullyValidateCertificate(const Certificate &certificate);

// Validates a CertificateChain message. Returns an OK status if and only if the
// message is valid.
//
// This function does NOT verify the contained certificate chain. It only checks
// that each certificate in |certificate_chain| is valid according to
// ValidateCertificate().
Status ValidateCertificateChain(const CertificateChain &certificate_chain);

// Validates a CertificateRevocationList message. Returns an OK status if and
// only if the message is valid.
//
// This function does NOT verify the contained CRL. It only checks that |crl|'s
// |format| and |data| fields are set and its |format| is not UNKNOWN.
Status ValidateCertificateRevocationList(const CertificateRevocationList &crl);

// Parses |certificate| and returns a CertificateInterface. Uses |factory_map|
// to determine which CertificateInterface factory to use for
// |certificate|.format(). Returns a non-OK Status if there were errors while
// parsing or if the format was unknown.
StatusOr<std::unique_ptr<CertificateInterface>> CreateCertificateInterface(
    const CertificateFactoryMap &factory_map, const Certificate &certificate);

// Parses |chain| and returns a CertificateInterfaceVector. Uses |factory_map|
// to determine which CertificateInterface factory to use for each format.
// Returns a non-OK Status if there were errors while parsing or if any format
// was unknown.
StatusOr<CertificateInterfaceVector> CreateCertificateChain(
    const CertificateFactoryMap &factory_map, const CertificateChain &chain);

// Checks if |certificate_chain| is a valid chain of certificates. The last
// certificate must be self-signed. Checks signatures and, depending on whether
// they are applicable for the format, checks the additional constraints set in
// |verification_config|. Returns a non-OK Status if the certificate chain is
// invalid, or if there were errors while verifying.
Status VerifyCertificateChain(CertificateInterfaceSpan certificate_chain,
                              const VerificationConfig &verification_config);

// Parses PEM-encoded certificate |pem_cert| into Certificate protobuf.
// Returns a non-OK Status if |pem_cert| is not X.509 PEM encoded.
StatusOr<Certificate> GetCertificateFromPem(absl::string_view pem_cert);

// Parses PEM-encoded certificate chain |pem_cert_chain| into CertificateChain
// protobuf. |pem_cert_chain| should be a series of X509 PEM-encoded
// certificates starting with "-----BEGIN CERTIFICATE-----" and ending with
// "-----END CERTIFICATE-----". Returns a non-OK Status if |pem_cert_chain|
// does not contain at least one pair of "-----BEGIN CERTIFICATE-----" to
// "-----END CERTIFICATE-----" or if any of the PEM certificates cannot be
// parsed as a PEM string.
StatusOr<CertificateChain> GetCertificateChainFromPem(
    absl::string_view pem_cert_chain);

// Parses PEM-encoded Certificate Revocation List (CRL) |pem_crl| into
// CertificateRevocationList protobuf. Returns a non-OK Status if
// |pem_crl| is not X.509 PEM encoded.
StatusOr<CertificateRevocationList> GetCrlFromPem(absl::string_view pem_crl);
}  // namespace asylo

#endif  // ASYLO_CRYPTO_CERTIFICATE_UTIL_H_
