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

#ifndef ASYLO_CRYPTO_X509_CERTIFICATE_UTIL_H_
#define ASYLO_CRYPTO_X509_CERTIFICATE_UTIL_H_

#include <openssl/base.h>
#include <openssl/x509.h>

#include <string>

#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_util_interface.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// An implementation of CertificateUtilInterface that can parse and verify
// X.509 certificates from PEM or DER encodings. This class is thread
// compatible.
class X509CertificateUtil : public CertificateUtilInterface {
 public:
  X509CertificateUtil() = default;

  // Creates and returns an X509 object equivalent to the data in |certificate|.
  // Returns a non-OK Status if the certificate could not be transformed to the
  // equivalent X.509 certificate.
  static StatusOr<bssl::UniquePtr<X509>> CertificateToX509(
      const Certificate &certificate);

  // From CertificateUtilInterface.

  Status VerifyCertificate(const Certificate &certificate,
                           ByteContainerView public_key_der) const override;

  StatusOr<std::string> ExtractSubjectKeyDer(
      const Certificate &certificate) const override;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_X509_CERTIFICATE_UTIL_H_
