/*
 *
 * Copyright 2018 Asylo authors
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

#ifndef ASYLO_CRYPTO_ECDSA_P256_SHA256_SIGNING_KEY_H_
#define ASYLO_CRYPTO_ECDSA_P256_SHA256_SIGNING_KEY_H_

#include <openssl/base.h>
#include <openssl/ec.h>

#include <cstdint>
#include <memory>
#include <string>

#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/util/statusor.h"

namespace asylo {

using EccP256Coordinate = UnsafeBytes<32>;

// Big-endian x and y coordinates of a point on the P256 curve.
struct EccP256CurvePoint {
  EccP256Coordinate x;
  EccP256Coordinate y;
};

// An implementation of the VerifyingKey interface that uses ECDSA-P256 keys for
// signature verification and SHA256 for message hashing.
class EcdsaP256Sha256VerifyingKey : public VerifyingKey {
 public:
  // Creates an ECDSA P256 verifying key from the given DER-encoded
  // |serialized_key|.
  static StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>> CreateFromDer(
      ByteContainerView serialized_key);

  // Creates an ECDSA P256 verifying key from the given PEM-encoded
  // |serialized_key|.
  static StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>> CreateFromPem(
      ByteContainerView serialized_key);

  // Creates an ECDSA P256 verifying key from the given |key_proto|.
  static StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>> CreateFromProto(
      const AsymmetricSigningKeyProto &key_proto);

  // Creates a new EcdsaP56VerifyingKey from the given |public_key|.
  static StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>> Create(
      bssl::UniquePtr<EC_KEY> public_key);

  // Creates a new EcdsaP56VerifyingKey from the given |public_key|.
  static StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>> Create(
      const EccP256CurvePoint &public_key);

  // From VerifyingKey.

  bool operator==(const VerifyingKey &other) const override;

  SignatureScheme GetSignatureScheme() const override;

  StatusOr<std::string> SerializeToDer() const override;

  StatusOr<std::string> SerializeToPem() const override;

  Status Verify(ByteContainerView message,
                ByteContainerView signature) const override;

  Status Verify(ByteContainerView message,
                const Signature &signature) const override;

 private:
  explicit EcdsaP256Sha256VerifyingKey(bssl::UniquePtr<EC_KEY> public_key);

  // An ECDSA P256 public key.
  bssl::UniquePtr<EC_KEY> public_key_;
};

// An implementation of the SigningKey interface that uses ECDSA-P256 keys for
// signing and SHA256 for message hashing.
class EcdsaP256Sha256SigningKey : public SigningKey {
 public:
  // Creates a random ECDSA P256 signing key.
  static StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>> Create();

  // Creates an ECDSA P256 signing key from the given DER-encoded
  // |serialized_key|.
  static StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>> CreateFromDer(
      ByteContainerView serialized_key);

  // Creates an ECDSA P256 signing key from the given PEM-encoded
  // |serialized_key|.
  static StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>> CreateFromPem(
      ByteContainerView serialized_key);

  // Creates an ECDSA P256 signing key from the given |key_proto|.
  static StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>> CreateFromProto(
      const AsymmetricSigningKeyProto &key_proto);

  // Creates an ECDSA P256 signing key from the given |private_key|.
  static StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>> Create(
      bssl::UniquePtr<EC_KEY> private_key);

  // From SigningKey.

  SignatureScheme GetSignatureScheme() const override;

  StatusOr<CleansingVector<uint8_t>> SerializeToDer() const override;

  StatusOr<CleansingVector<char>> SerializeToPem() const override;

  StatusOr<std::unique_ptr<VerifyingKey>> GetVerifyingKey() const override;

  Status Sign(ByteContainerView message,
              std::vector<uint8_t> *signature) const override;

  Status Sign(ByteContainerView message, Signature *signature) const override;

  Status SignX509(X509 *x509) const override;

  StatusOr<EccP256CurvePoint> GetPublicKeyPoint() const;

 private:
  EcdsaP256Sha256SigningKey(bssl::UniquePtr<EC_KEY> private_key,
                            bssl::UniquePtr<EC_KEY> public_key);

  // An ECDSA P256 private key.
  bssl::UniquePtr<EC_KEY> private_key_;

  // An ECDSA P256 public key that can verify signatures produced by
  // private_key_.
  bssl::UniquePtr<EC_KEY> public_key_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_ECDSA_P256_SHA256_SIGNING_KEY_H_
