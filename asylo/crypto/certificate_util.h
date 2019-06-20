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

#include "asylo/crypto/certificate.pb.h"
#include "asylo/util/status.h"

namespace asylo {

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

}  // namespace asylo

#endif  // ASYLO_CRYPTO_CERTIFICATE_UTIL_H_
