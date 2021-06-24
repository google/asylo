/*
 * Copyright 2020 Asylo authors
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
 */

#ifndef ASYLO_CRYPTO_RSA_2048_SIGNING_KEY_H_
#define ASYLO_CRYPTO_RSA_2048_SIGNING_KEY_H_

#include <openssl/base.h>
#include <openssl/rsa.h>

#include <memory>
#include <string>

#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/x509_signer.h"
#include "asylo/util/cleansing_types.h"

namespace asylo {

// An implementation of the X509Signer interface that uses RSA keys with the
// given algorithm for signing.
class RsaX509Signer : public X509Signer {
 public:
  enum SignatureAlgorithm {
    RSASSA_PSS_WITH_SHA384,
  };

  // Creates an RSA X509Signer from the given PEM-encoded
  // |serialized_private_key|, with signature algorithm |signature_algorithm|.
  static StatusOr<std::unique_ptr<RsaX509Signer>> CreateFromPem(
      ByteContainerView serialized_private_key,
      SignatureAlgorithm signature_algorithm);

  int KeySizeInBits() const;

  StatusOr<std::string> SerializePublicKeyToDer() const override;

  // From X509Signer.
  StatusOr<CleansingVector<char>> SerializeToPem() const override;

  Status SignX509(X509* x509) const override;

  Status SignX509Req(X509_REQ* x509_req) const override;

 private:
  RsaX509Signer(bssl::UniquePtr<RSA> private_key,
                SignatureAlgorithm signature_algorithm);

  bssl::UniquePtr<RSA> private_key_;
  SignatureAlgorithm signature_algorithm_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_RSA_2048_SIGNING_KEY_H_
