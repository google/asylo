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

#ifndef ASYLO_CRYPTO_ECDSA_SIGNING_KEY_H_
#define ASYLO_CRYPTO_ECDSA_SIGNING_KEY_H_

#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/bignum_util.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace internal {

// Helper functions.
StatusOr<bssl::UniquePtr<EC_KEY>> CreatePublicKeyFromPrivateKey(
    EC_KEY *private_key, int nid);
Status CheckKeyProtoValues(const AsymmetricSigningKeyProto &key_proto,
                           AsymmetricSigningKeyProto::KeyType expected_type,
                           SignatureScheme signature_scheme);

template <int32_t kCoordinateSize>
StatusOr<UnsafeBytes<kCoordinateSize>> ToCoordinate(const BIGNUM &bignum) {
  UnsafeBytes<kCoordinateSize> coordinate;
  if (BN_bn2bin_padded(coordinate.data(), coordinate.size(), &bignum) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return coordinate;
}

template <class Hash>
Status DoHash(ByteContainerView message, std::vector<uint8_t> *digest) {
  Hash hasher;
  hasher.Update(message);
  return hasher.CumulativeHash(digest);
}

template <class Hash>
Status BsslSignX509(X509 *x509, EC_KEY *private_key) {
  bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
  if (EVP_PKEY_set1_EC_KEY(evp_pkey.get(), private_key) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  Hash hasher;
  if (X509_sign(x509, evp_pkey.get(), hasher.GetBsslHashFunction()) == 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

template <class Hash>
Status BsslSignX509Req(X509_REQ *x509_req, EC_KEY *private_key) {
  bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
  if (EVP_PKEY_set1_EC_KEY(evp_pkey.get(), private_key) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  Hash hasher;
  if (X509_REQ_sign(x509_req, evp_pkey.get(), hasher.GetBsslHashFunction()) ==
      0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

// Boring SSL Helper functions to create keys.
StatusOr<bssl::UniquePtr<EC_KEY>> GetPublicEcKeyFromDer(
    ByteContainerView serialized_key);
StatusOr<bssl::UniquePtr<EC_KEY>> GetPublicEcKeyFromPem(
    ByteContainerView serialized_key);
StatusOr<bssl::UniquePtr<EC_KEY>> GetPublicEcKeyFromCurvePoint(int nid,
                                                               const BIGNUM *x,
                                                               const BIGNUM *y);
StatusOr<bssl::UniquePtr<EC_KEY>> CreatePrivateEcKey(int nid);
StatusOr<bssl::UniquePtr<EC_KEY>> CreatePrivateEcKeyFromDer(
    int nid, ByteContainerView serialized_key);
StatusOr<bssl::UniquePtr<EC_KEY>> CreatePrivateEcKeyFromPem(
    ByteContainerView serialized_key);
StatusOr<bssl::UniquePtr<EC_KEY>> CreatePrivateEcKeyFromScalar(
    int nid, const BIGNUM *scalar);

// Boring SSL Helper functions to serialize keys.
StatusOr<std::string> BsslSerializePublicKeyToDer(const EC_KEY *public_key);
StatusOr<std::string> BsslSerializePublicKeyToPem(EC_KEY *public_key);
StatusOr<CleansingVector<uint8_t>> BsslSerializePrivateKeyToDer(
    const EC_KEY *private_key);
StatusOr<CleansingVector<char>> BsslSerializePrivateKeyToPem(
    EC_KEY *private_key);

// Boring SSL Helper functions for signing and verifying.
Status EcdsaSign(std::vector<uint8_t> *signature, ByteContainerView digest,
                 const EC_KEY *private_key);
Status EcdsaSignDigestAndSetRS(SignatureScheme sig_scheme,
                               ByteContainerView digest,
                               const EC_KEY *private_key,
                               int32_t coordinate_size, Signature *signature);
Status VerifyEcdsa(ByteContainerView digest, ByteContainerView signature,
                   const EC_KEY *public_key);
Status VerifyEcdsaWithRS(ByteContainerView r, ByteContainerView s,
                         ByteContainerView digest, const EC_KEY *public_key);

// Miscellaneous Boring SSL Helper functions.
int GetEcCurveNid(const EC_KEY *key);
bool PublicKeyCompare(const EC_KEY *key1, const EC_KEY *key2);  // vk
StatusOr<bssl::UniquePtr<EC_KEY>> GetPublicEcKey(const EC_KEY *public_key);
StatusOr<std::pair<bssl::UniquePtr<BIGNUM>, bssl::UniquePtr<BIGNUM>>>
GetEcdsaPoint(const EC_KEY *private_key);

// Big-endian x and y coordinates of a point on an ECDSA curve.
template <size_t kCoordinateSize>
struct EccCurvePoint {
  UnsafeBytes<kCoordinateSize> x;
  UnsafeBytes<kCoordinateSize> y;
};

// An implementation of the VerifyingKey interface that uses an ECDSA key for
// signature verification.
template <SignatureScheme kSignatureScheme, int kNid, int32_t kCoordinateSize,
          class Hash>
class EcdsaVerifyingKey : public VerifyingKey {
  static_assert(std::is_base_of<HashInterface, Hash>::value);

 public:
  // Creates an ECDSA verifying key from the given DER-encoded
  // |serialized_key|.
  static StatusOr<std::unique_ptr<
      EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
  CreateFromDer(ByteContainerView serialized_key) {
    bssl::UniquePtr<EC_KEY> key;
    ASYLO_ASSIGN_OR_RETURN(key, GetPublicEcKeyFromDer(serialized_key));
    return Create(std::move(key));
  }

  // Creates an ECDSA verifying key from the given PEM-encoded
  // |serialized_key|.
  static StatusOr<std::unique_ptr<
      EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
  CreateFromPem(ByteContainerView serialized_key) {
    bssl::UniquePtr<EC_KEY> key;
    ASYLO_ASSIGN_OR_RETURN(key, GetPublicEcKeyFromPem(serialized_key));

    return Create(std::move(key));
  }

  // Creates an ECDSA verifying key from the given |key_proto|.
  static StatusOr<std::unique_ptr<
      EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
  CreateFromProto(const AsymmetricSigningKeyProto &key_proto);

  // Creates a new EcdsaVerifyingKey from the given |public_key|.
  static StatusOr<std::unique_ptr<
      EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
  Create(bssl::UniquePtr<EC_KEY> public_key);

  // Creates a new EcdsaVerifyingKey from the given |public_key|.
  static StatusOr<std::unique_ptr<
      EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
  Create(const EccCurvePoint<kCoordinateSize> &public_key);

  // From VerifyingKey.

  bool operator==(const VerifyingKey &other) const override;

  SignatureScheme GetSignatureScheme() const override {
    return kSignatureScheme;
  }

  StatusOr<std::string> SerializeToDer() const override {
    return BsslSerializePublicKeyToDer(public_key_.get());
  }

  StatusOr<std::string> SerializeToPem() const override {
    return BsslSerializePublicKeyToPem(public_key_.get());
  }

  Status Verify(ByteContainerView message,
                ByteContainerView signature) const override {
    std::vector<uint8_t> digest;
    ASYLO_RETURN_IF_ERROR(DoHash<Hash>(message, &digest));

    return VerifyEcdsa(digest, signature, public_key_.get());
  }

  Status Verify(ByteContainerView message,
                const Signature &signature) const override;

 private:
  explicit EcdsaVerifyingKey(bssl::UniquePtr<EC_KEY> public_key)
      : public_key_(std::move(public_key)) {}

  // An ECDSA public key.
  bssl::UniquePtr<EC_KEY> public_key_;
};

// An implementation of the SigningKey interface that uses an ECDSA key for
// signing.
template <SignatureScheme kSignatureScheme, int kNid, int32_t kCoordinateSize,
          class Hash>
class EcdsaSigningKey : public SigningKey {
  static_assert(std::is_base_of<HashInterface, Hash>::value);

 public:
  // Creates a random ECDSA signing key.
  static StatusOr<std::unique_ptr<
      EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
  Create() {
    bssl::UniquePtr<EC_KEY> key;
    ASYLO_ASSIGN_OR_RETURN(key, CreatePrivateEcKey(kNid));
    return Create(std::move(key));
  }

  // Creates an ECDSA signing key from the given DER-encoded
  // |serialized_key|.
  static StatusOr<std::unique_ptr<
      EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
  CreateFromDer(ByteContainerView serialized_key) {
    bssl::UniquePtr<EC_KEY> key;
    ASYLO_ASSIGN_OR_RETURN(key,
                           CreatePrivateEcKeyFromDer(kNid, serialized_key));

    return Create(std::move(key));
  }

  // Creates an ECDSA signing key from the given PEM-encoded
  // |serialized_key|.
  static StatusOr<std::unique_ptr<
      EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
  CreateFromPem(ByteContainerView serialized_key) {
    bssl::UniquePtr<EC_KEY> key;
    ASYLO_ASSIGN_OR_RETURN(key, CreatePrivateEcKeyFromPem(serialized_key));
    return Create(std::move(key));
  }

  // Creates an ECDSA signing key from the given |key_proto|.
  static StatusOr<std::unique_ptr<
      EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
  CreateFromProto(const AsymmetricSigningKeyProto &key_proto);

  // Creates an ECDSA signing key from the given |scalar|.
  static StatusOr<std::unique_ptr<
      EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
  CreateFromScalar(ByteContainerView scalar);

  // Creates an ECDSA signing key from the given |private_key|.
  static StatusOr<std::unique_ptr<
      EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
  Create(bssl::UniquePtr<EC_KEY> private_key);

  // From SigningKey.

  SignatureScheme GetSignatureScheme() const override {
    return kSignatureScheme;
  }

  StatusOr<CleansingVector<uint8_t>> SerializeToDer() const override {
    return BsslSerializePrivateKeyToDer(private_key_.get());
  }

  StatusOr<CleansingVector<char>> SerializeToPem() const override {
    return BsslSerializePrivateKeyToPem(private_key_.get());
  }

  StatusOr<std::unique_ptr<VerifyingKey>> GetVerifyingKey() const override {
    bssl::UniquePtr<EC_KEY> public_key_copy;
    ASYLO_ASSIGN_OR_RETURN(public_key_copy, GetPublicEcKey(public_key_.get()));

    return EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize,
                             Hash>::Create(std::move(public_key_copy));
  }

  Status Sign(ByteContainerView message,
              std::vector<uint8_t> *signature) const override {
    std::vector<uint8_t> digest;
    ASYLO_RETURN_IF_ERROR(DoHash<Hash>(message, &digest));

    return EcdsaSign(signature, digest, private_key_.get());
  }

  Status Sign(ByteContainerView message, Signature *signature) const override {
    std::vector<uint8_t> digest;
    ASYLO_RETURN_IF_ERROR(DoHash<Hash>(message, &digest));

    ASYLO_RETURN_IF_ERROR(EcdsaSignDigestAndSetRS(GetSignatureScheme(), digest,
                                                  private_key_.get(),
                                                  kCoordinateSize, signature));
    return absl::OkStatus();
  }

  // From X509Signer.

  StatusOr<std::string> SerializePublicKeyToDer() const override {
    return BsslSerializePublicKeyToDer(public_key_.get());
  }

  Status SignX509(X509 *x509) const override {
    return BsslSignX509<Hash>(x509, private_key_.get());
  }

  Status SignX509Req(X509_REQ *x509_req) const override {
    return BsslSignX509Req<Hash>(x509_req, private_key_.get());
  }

  StatusOr<EccCurvePoint<kCoordinateSize>> GetPublicKeyPoint() const;

 private:
  EcdsaSigningKey(bssl::UniquePtr<EC_KEY> private_key,
                  bssl::UniquePtr<EC_KEY> public_key)
      : private_key_(std::move(private_key)),
        public_key_(std::move(public_key)) {}

  int32_t getSignatureParamSize();

  // An ECDSA private key.
  bssl::UniquePtr<EC_KEY> private_key_;

  // An ECDSA public key that can verify signatures produced by
  // private_key_.
  bssl::UniquePtr<EC_KEY> public_key_;
};

// EcdsaVerifyingKey methods CreateFromProto, Create (2 overloads), and methods
// from VerifyingKey.

template <SignatureScheme kSignatureScheme, int kNid, int32_t kCoordinateSize,
          class Hash>
StatusOr<std::unique_ptr<
    EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>::
    CreateFromProto(const AsymmetricSigningKeyProto &key_proto) {
  ASYLO_RETURN_IF_ERROR(CheckKeyProtoValues(
      key_proto, AsymmetricSigningKeyProto::VERIFYING_KEY, kSignatureScheme));

  switch (key_proto.encoding()) {
    case ASYMMETRIC_KEY_DER:
      return CreateFromDer(key_proto.key());
    case ASYMMETRIC_KEY_PEM:
      return CreateFromPem(key_proto.key());
    default:
      break;
  }
  return Status(absl::StatusCode::kUnimplemented,
                absl::StrFormat("Asymmetric key encoding (%s) unsupported",
                                ProtoEnumValueName(key_proto.encoding())));
}

// Creates a new EcdsaP256VerifyingKey from the given |public_key|.
template <SignatureScheme kSignatureScheme, int kNid, int32_t kCoordinateSize,
          class Hash>
StatusOr<std::unique_ptr<
    EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>::Create(
    bssl::UniquePtr<EC_KEY> public_key) {
  if (GetEcCurveNid(public_key.get()) != kNid) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        "public_key parameter must represent a point on the NIST  curve");
  }

  return absl::WrapUnique<
      EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>(
      new EcdsaVerifyingKey(std::move(public_key)));
}

// Creates a new EcdsaVerifyingKey from the given |public_key|.
template <SignatureScheme kSignatureScheme, int kNid, int32_t kCoordinateSize,
          class Hash>
StatusOr<std::unique_ptr<
    EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>::Create(
    const EccCurvePoint<kCoordinateSize> &public_key) {
  bssl::UniquePtr<BIGNUM> bignum_x;
  ASYLO_ASSIGN_OR_RETURN(bignum_x, BignumFromBigEndianBytes(public_key.x));

  bssl::UniquePtr<BIGNUM> bignum_y;
  ASYLO_ASSIGN_OR_RETURN(bignum_y, BignumFromBigEndianBytes(public_key.y));

  bssl::UniquePtr<EC_KEY> key;
  ASYLO_ASSIGN_OR_RETURN(
      key, GetPublicEcKeyFromCurvePoint(kNid, bignum_x.get(), bignum_y.get()));

  return Create(std::move(key));
}

template <SignatureScheme kSignatureScheme, int kNid, int32_t kCoordinateSize,
          class Hash>
bool EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize,
                       Hash>::operator==(const VerifyingKey &other) const {
  EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize,
                    Hash> const *other_key =
      dynamic_cast<EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize,
                                     Hash> const *>(&other);
  if (other_key == nullptr) {
    return false;
  }

  return PublicKeyCompare(public_key_.get(), other_key->public_key_.get());
}

template <SignatureScheme kSignatureScheme, int kNid, int32_t kCoordinateSize,
          class Hash>
Status EcdsaVerifyingKey<kSignatureScheme, kNid, kCoordinateSize, Hash>::Verify(
    ByteContainerView message, const Signature &signature) const {
  if (signature.signature_scheme() != GetSignatureScheme()) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Signature scheme should be %s, instead is %s",
                        ProtoEnumValueName(GetSignatureScheme()),
                        ProtoEnumValueName(signature.signature_scheme())));
  }

  if (!signature.has_ecdsa_signature()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Signature does not have an ECDSA signature");
  }

  if (!signature.ecdsa_signature().has_r() ||
      !signature.ecdsa_signature().has_s()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "Signature must include an R and an S value");
  }

  if (signature.ecdsa_signature().r().size() != kCoordinateSize ||
      signature.ecdsa_signature().s().size() != kCoordinateSize) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("The R and S values must each be ",
                               kCoordinateSize, " bytes"));
  }

  std::vector<uint8_t> digest;
  ASYLO_RETURN_IF_ERROR(DoHash<Hash>(message, &digest));

  return VerifyEcdsaWithRS(signature.ecdsa_signature().r(),
                           signature.ecdsa_signature().s(), digest,
                           public_key_.get());
}

// EcdsaSigningKey methods CreateFromProto, Create, CreateFromScalar, and
// methods from SigningKey.

template <SignatureScheme kSignatureScheme, int kNid, int32_t kCoordinateSize,
          class Hash>
StatusOr<std::unique_ptr<
    EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>::CreateFromProto(
    const AsymmetricSigningKeyProto &key_proto) {
  ASYLO_RETURN_IF_ERROR(CheckKeyProtoValues(
      key_proto, AsymmetricSigningKeyProto::SIGNING_KEY, kSignatureScheme));

  switch (key_proto.encoding()) {
    case ASYMMETRIC_KEY_DER:
      return CreateFromDer(key_proto.key());
    case ASYMMETRIC_KEY_PEM:
      return CreateFromPem(key_proto.key());
    case UNKNOWN_ASYMMETRIC_KEY_ENCODING:
      break;
  }
  return Status(absl::StatusCode::kUnimplemented,
                absl::StrFormat("Asymmetric key encoding (%d) unsupported",
                                key_proto.encoding()));
}

template <SignatureScheme kSignatureScheme, int kNid, int32_t kCoordinateSize,
          class Hash>
StatusOr<std::unique_ptr<
    EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize,
                Hash>::CreateFromScalar(ByteContainerView scalar) {
  if (scalar.size() != kCoordinateSize) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrFormat("Size of scalar (%d) must be %d",
                                  scalar.size(), kCoordinateSize));
  }

  bssl::UniquePtr<BIGNUM> bignum_scalar;
  ASYLO_ASSIGN_OR_RETURN(bignum_scalar, BignumFromBigEndianBytes(scalar));

  bssl::UniquePtr<EC_KEY> key;
  ASYLO_ASSIGN_OR_RETURN(
      key, CreatePrivateEcKeyFromScalar(kNid, bignum_scalar.get()));

  return Create(std::move(key));
}

template <SignatureScheme kSignatureScheme, int kNid, int32_t kCoordinateSize,
          class Hash>
StatusOr<std::unique_ptr<
    EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>>>
EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>::Create(
    bssl::UniquePtr<EC_KEY> private_key) {
  if (GetEcCurveNid(private_key.get()) != kNid) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "private_key parameter must be a key for the NIST  curve");
  }

  auto public_key_result =
      CreatePublicKeyFromPrivateKey(private_key.get(), kNid);
  if (!public_key_result.ok()) {
    return public_key_result.status();
  }

  return absl::WrapUnique<EcdsaSigningKey>(
      new EcdsaSigningKey<kSignatureScheme, kNid, kCoordinateSize, Hash>(
          std::move(private_key), std::move(public_key_result).value()));
}

template <SignatureScheme kSignatureScheme, int kNid, int32_t kCoordinateSize,
          class Hash>
StatusOr<EccCurvePoint<kCoordinateSize>> EcdsaSigningKey<
    kSignatureScheme, kNid, kCoordinateSize, Hash>::GetPublicKeyPoint() const {
  EccCurvePoint<kCoordinateSize> public_key;
  std::pair<bssl::UniquePtr<BIGNUM>, bssl::UniquePtr<BIGNUM>> key_point;

  ASYLO_ASSIGN_OR_RETURN(key_point, GetEcdsaPoint(private_key_.get()));

  ASYLO_ASSIGN_OR_RETURN(public_key.x,
                         ToCoordinate<kCoordinateSize>(*(key_point.first)));
  ASYLO_ASSIGN_OR_RETURN(public_key.y,
                         ToCoordinate<kCoordinateSize>(*(key_point.second)));
  return public_key;
}

}  // namespace internal
}  // namespace asylo

#endif  // ASYLO_CRYPTO_ECDSA_SIGNING_KEY_H_
