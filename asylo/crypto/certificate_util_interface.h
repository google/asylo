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

#ifndef ASYLO_CRYPTO_CERTIFICATE_UTIL_INTERFACE_H_
#define ASYLO_CRYPTO_CERTIFICATE_UTIL_INTERFACE_H_

#include <string>

#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// CertificateUtilInterface defines an interface for operations on certificates.
class CertificateUtilInterface {
 public:
  virtual ~CertificateUtilInterface() = default;

  // Checks if |certificate| can be verified by a key created from
  // |public_key_der|. Returns a non-OK Status if there was an error, or if
  // verification fails.
  virtual Status VerifyCertificate(const Certificate &certificate,
                                   ByteContainerView public_key_der) const = 0;

  // Returns the DER-encoded public key certified by |certificate|. Returns a
  // non-OK Status if there was an error.
  virtual StatusOr<std::string> ExtractSubjectKeyDer(
      const Certificate &certificate) const = 0;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_CERTIFICATE_UTIL_INTERFACE_H_
