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

#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"

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
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/bignum_util.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

constexpr int32_t kSignatureParamSize = 32;

// Returns an EC_KEY containing the public key corresponding to |private_key|.
StatusOr<bssl::UniquePtr<EC_KEY>> CreatePublicKeyFromPrivateKey(
    const EC_KEY *private_key) {
  bssl::UniquePtr<EC_KEY> public_key(
      EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (!public_key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  if (!EC_KEY_set_public_key(public_key.get(),
                             EC_KEY_get0_public_key(private_key))) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return std::move(public_key);
}

Status DoSha256Hash(ByteContainerView message, std::vector<uint8_t> *digest) {
  Sha256Hash hasher;
  hasher.Init();
  hasher.Update(message);
  return hasher.CumulativeHash(digest);
}

Status CheckKeyProtoValues(const AsymmetricSigningKeyProto &key_proto,
                           AsymmetricSigningKeyProto::KeyType expected_type) {
  if (key_proto.key_type() != expected_type) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrFormat("Key type of the key (%s) does not match the expected "
                        "key type (%s)",
                        ProtoEnumValueName(key_proto.key_type()),
                        ProtoEnumValueName(expected_type)));
  }

  if (key_proto.signature_scheme() != ECDSA_P256_SHA256) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrFormat("Signature scheme of the key (%s) does not match the "
                        "expected signature scheme (%s)",
                        ProtoEnumValueName(key_proto.signature_scheme()),
                        ProtoEnumValueName(ECDSA_P256_SHA256)));
  }
  return Status::OkStatus();
}

StatusOr<EccP256Coordinate> ToCoordinate(const BIGNUM &bignum) {
  EccP256Coordinate coordinate;
  if (BN_bn2bin_padded(coordinate.data(), coordinate.size(), &bignum) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return coordinate;
}

}  // namespace

// EcdsaP256Sha256VerifyingKey

StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>>
EcdsaP256Sha256VerifyingKey::CreateFromDer(ByteContainerView serialized_key) {
  // The input data containing the serialized public key.
  uint8_t const *serialized_key_data = serialized_key.data();

  // Create a public key from the input data. If |a| was set, the EC_KEY object
  // referenced by |a| would be freed and |a| would be updated to point to the
  // returned object.
  bssl::UniquePtr<EC_KEY> key(d2i_EC_PUBKEY(/*a=*/nullptr, &serialized_key_data,
                                            serialized_key.size()));
  if (!key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return Create(std::move(key));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>>
EcdsaP256Sha256VerifyingKey::CreateFromPem(ByteContainerView serialized_key) {
  // The input bio object containing the serialized public key.
  bssl::UniquePtr<BIO> key_bio(
      BIO_new_mem_buf(serialized_key.data(), serialized_key.size()));

  // Create a public key from the input PEM data. For more information, see
  // https://www.openssl.org/docs/man1.1.0/man3/PEM_read_bio_EC_PUBKEY.html.
  bssl::UniquePtr<EC_KEY> key(PEM_read_bio_EC_PUBKEY(
      key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));
  if (!key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return Create(std::move(key));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>>
EcdsaP256Sha256VerifyingKey::CreateFromProto(
    const AsymmetricSigningKeyProto &key_proto) {
  ASYLO_RETURN_IF_ERROR(
      CheckKeyProtoValues(key_proto, AsymmetricSigningKeyProto::VERIFYING_KEY));

  switch (key_proto.encoding()) {
    case ASYMMETRIC_KEY_DER:
      return CreateFromDer(key_proto.key());
    case ASYMMETRIC_KEY_PEM:
      return CreateFromPem(key_proto.key());
    default:
      break;
  }
  return Status(error::GoogleError::UNIMPLEMENTED,
                absl::StrFormat("Asymmetric key encoding (%s) unsupported",
                                ProtoEnumValueName(key_proto.encoding())));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>>
EcdsaP256Sha256VerifyingKey::Create(bssl::UniquePtr<EC_KEY> public_key) {
  if (EC_GROUP_get_curve_name(EC_KEY_get0_group(public_key.get())) !=
      NID_X9_62_prime256v1) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        "public_key parameter must represent a point on the NIST P256 curve");
  }

  return absl::WrapUnique<EcdsaP256Sha256VerifyingKey>(
      new EcdsaP256Sha256VerifyingKey(std::move(public_key)));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256VerifyingKey>>
EcdsaP256Sha256VerifyingKey::Create(const EccP256CurvePoint &public_key) {
  bssl::UniquePtr<BIGNUM> bignum_x;
  ASYLO_ASSIGN_OR_RETURN(bignum_x, BignumFromBigEndianBytes(public_key.x));

  bssl::UniquePtr<BIGNUM> bignum_y;
  ASYLO_ASSIGN_OR_RETURN(bignum_y, BignumFromBigEndianBytes(public_key.y));

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  CHECK(key != nullptr);

  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group));
  if (EC_POINT_set_affine_coordinates_GFp(group, point.get(), bignum_x.get(),
                                          bignum_y.get(),
                                          /*ctx=*/nullptr) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  if (EC_KEY_set_public_key(key.get(), point.get()) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return Create(std::move(key));
}

bool EcdsaP256Sha256VerifyingKey::operator==(const VerifyingKey &other) const {
  EcdsaP256Sha256VerifyingKey const *other_key =
      dynamic_cast<EcdsaP256Sha256VerifyingKey const *>(&other);
  if (other_key == nullptr) {
    return false;
  }

  const EC_GROUP *group = EC_KEY_get0_group(public_key_.get());
  const EC_GROUP *other_group = EC_KEY_get0_group(other_key->public_key_.get());

  const EC_POINT *point = EC_KEY_get0_public_key(public_key_.get());
  const EC_POINT *other_point =
      EC_KEY_get0_public_key(other_key->public_key_.get());

  return (EC_GROUP_cmp(group, other_group, /*ignored=*/nullptr) == 0) &&
         (EC_POINT_cmp(group, point, other_point, /*ctx=*/nullptr) == 0);
}

SignatureScheme EcdsaP256Sha256VerifyingKey::GetSignatureScheme() const {
  return SignatureScheme::ECDSA_P256_SHA256;
}

StatusOr<std::string> EcdsaP256Sha256VerifyingKey::SerializeToDer() const {
  uint8_t *key = nullptr;
  int length = i2d_EC_PUBKEY(public_key_.get(), &key);
  if (length <= 0) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  bssl::UniquePtr<uint8_t> deleter(key);
  return std::string(reinterpret_cast<char *>(key), length);
}

StatusOr<std::string> EcdsaP256Sha256VerifyingKey::SerializeToPem() const {
  bssl::UniquePtr<BIO> key_bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_EC_PUBKEY(key_bio.get(), public_key_.get())) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  size_t key_data_size;
  const uint8_t *key_data = nullptr;
  if (BIO_mem_contents(key_bio.get(), &key_data, &key_data_size) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return std::string(reinterpret_cast<const char *>(key_data), key_data_size);
}

Status EcdsaP256Sha256VerifyingKey::Verify(ByteContainerView message,
                                           ByteContainerView signature) const {
  std::vector<uint8_t> digest;
  ASYLO_RETURN_IF_ERROR(DoSha256Hash(message, &digest));

  if (ECDSA_verify(/*type=*/0, digest.data(), digest.size(), signature.data(),
                   signature.size(), public_key_.get()) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return Status::OkStatus();
}

Status EcdsaP256Sha256VerifyingKey::Verify(ByteContainerView message,
                                           const Signature &signature) const {
  if (signature.signature_scheme() != GetSignatureScheme()) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrFormat("Signature scheme should be %s, instead is %s",
                        ProtoEnumValueName(GetSignatureScheme()),
                        ProtoEnumValueName(signature.signature_scheme())));
  }

  if (!signature.has_ecdsa_signature()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Signature does not have an ECDSA signature");
  }

  if (!signature.ecdsa_signature().has_r() ||
      !signature.ecdsa_signature().has_s()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Signature must include an R and an S value");
  }

  if (signature.ecdsa_signature().r().size() != kSignatureParamSize ||
      signature.ecdsa_signature().s().size() != kSignatureParamSize) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrCat("The R and S values must each be ",
                               kSignatureParamSize, " bytes"));
  }

  std::vector<uint8_t> digest;
  ASYLO_RETURN_IF_ERROR(DoSha256Hash(message, &digest));

  bssl::UniquePtr<BIGNUM> r;
  ASYLO_ASSIGN_OR_RETURN(
      r, BignumFromBigEndianBytes(signature.ecdsa_signature().r()));
  bssl::UniquePtr<BIGNUM> s;
  ASYLO_ASSIGN_OR_RETURN(
      s, BignumFromBigEndianBytes(signature.ecdsa_signature().s()));

  bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_new());
  if (ECDSA_SIG_set0(sig.get(), r.release(), s.release()) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  if (ECDSA_do_verify(digest.data(), digest.size(), sig.get(),
                      public_key_.get()) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return Status::OkStatus();
}

EcdsaP256Sha256VerifyingKey::EcdsaP256Sha256VerifyingKey(
    bssl::UniquePtr<EC_KEY> public_key)
    : public_key_(std::move(public_key)) {}

// EcdsaP256Sha256SigningKey

StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>>
EcdsaP256Sha256SigningKey::Create() {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (!key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  int result = 0;
  if (FIPS_mode()) {
    result = EC_KEY_generate_key_fips(key.get());
  } else {
    result = EC_KEY_generate_key(key.get());
  }
  if (!result) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return Create(std::move(key));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>>
EcdsaP256Sha256SigningKey::CreateFromDer(ByteContainerView serialized_key) {
  CBS buffer;
  CBS_init(&buffer, serialized_key.data(), serialized_key.size());

  bssl::UniquePtr<EC_GROUP> group(
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  if (!group) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_parse_private_key(&buffer, group.get()));
  if (!key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return Create(std::move(key));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>>
EcdsaP256Sha256SigningKey::CreateFromPem(ByteContainerView serialized_key) {
  // The input bio object containing the serialized public key.
  bssl::UniquePtr<BIO> key_bio(
      BIO_new_mem_buf(serialized_key.data(), serialized_key.size()));

  // Create a private key from the input PEM data.
  bssl::UniquePtr<EC_KEY> key(PEM_read_bio_ECPrivateKey(
      key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));
  if (!key) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return Create(std::move(key));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>>
EcdsaP256Sha256SigningKey::CreateFromProto(
    const AsymmetricSigningKeyProto &key_proto) {
  ASYLO_RETURN_IF_ERROR(
      CheckKeyProtoValues(key_proto, AsymmetricSigningKeyProto::SIGNING_KEY));

  switch (key_proto.encoding()) {
    case ASYMMETRIC_KEY_DER:
      return CreateFromDer(key_proto.key());
    case ASYMMETRIC_KEY_PEM:
      return CreateFromPem(key_proto.key());
    case UNKNOWN_ASYMMETRIC_KEY_ENCODING:
      return Status(error::GoogleError::UNIMPLEMENTED,
                    absl::StrFormat("Asymmetric key encoding (%s) unsupported",
                                    ProtoEnumValueName(key_proto.encoding())));
  }
  return Status(error::GoogleError::UNIMPLEMENTED,
                absl::StrFormat("Asymmetric key encoding (%d) unsupported",
                                key_proto.encoding()));
}

StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>>
EcdsaP256Sha256SigningKey::Create(bssl::UniquePtr<EC_KEY> private_key) {
  if (EC_GROUP_get_curve_name(EC_KEY_get0_group(private_key.get())) !=
      NID_X9_62_prime256v1) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        "private_key parameter must be a key for the NIST P256 curve");
  }

  auto public_key_result = CreatePublicKeyFromPrivateKey(private_key.get());
  if (!public_key_result.ok()) {
    return public_key_result.status();
  }

  return absl::WrapUnique<EcdsaP256Sha256SigningKey>(
      new EcdsaP256Sha256SigningKey(std::move(private_key),
                                    std::move(public_key_result).ValueOrDie()));
}

StatusOr<CleansingVector<uint8_t>> EcdsaP256Sha256SigningKey::SerializeToDer()
    const {
  CBB buffer;
  if (!CBB_init(&buffer, /*initial_capacity=*/0) ||
      !EC_KEY_marshal_private_key(&buffer, private_key_.get(),
                                  EC_KEY_get_enc_flags(private_key_.get()))) {
    CBB_cleanup(&buffer);
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  uint8_t *key_data;
  size_t key_data_size = 0;
  CBB_finish(&buffer, &key_data, &key_data_size);

  CleansingVector<uint8_t> serialized_key(key_data, key_data + key_data_size);

  OPENSSL_cleanse(key_data, key_data_size);
  OPENSSL_free(key_data);

  return serialized_key;
}

StatusOr<CleansingVector<char>> EcdsaP256Sha256SigningKey::SerializeToPem()
    const {
  bssl::UniquePtr<BIO> key_bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_ECPrivateKey(key_bio.get(), private_key_.get(),
                                  /*enc=*/nullptr, /*kstr=*/nullptr, /*klen=*/0,
                                  /*cb=*/nullptr, /*u=*/nullptr)) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  size_t key_data_size;
  const uint8_t *key_data = nullptr;
  if (BIO_mem_contents(key_bio.get(), &key_data, &key_data_size) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return CleansingVector<char>(key_data, key_data + key_data_size);
}

SignatureScheme EcdsaP256Sha256SigningKey::GetSignatureScheme() const {
  return SignatureScheme::ECDSA_P256_SHA256;
}

StatusOr<std::unique_ptr<VerifyingKey>>
EcdsaP256Sha256SigningKey::GetVerifyingKey() const {
  bssl::UniquePtr<EC_KEY> public_key_copy(EC_KEY_dup(public_key_.get()));
  if (!public_key_copy) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  return EcdsaP256Sha256VerifyingKey::Create(std::move(public_key_copy));
}

Status EcdsaP256Sha256SigningKey::Sign(ByteContainerView message,
                                       std::vector<uint8_t> *signature) const {
  std::vector<uint8_t> digest;
  ASYLO_RETURN_IF_ERROR(DoSha256Hash(message, &digest));

  signature->resize(ECDSA_size(private_key_.get()));
  uint32_t signature_size = 0;
  if (!ECDSA_sign(/*type=*/0, digest.data(), digest.size(), signature->data(),
                  &signature_size, private_key_.get())) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  signature->resize(signature_size);
  return Status::OkStatus();
}

Status EcdsaP256Sha256SigningKey::Sign(ByteContainerView message,
                                       Signature *signature) const {
  std::vector<uint8_t> digest;
  ASYLO_RETURN_IF_ERROR(DoSha256Hash(message, &digest));

  bssl::UniquePtr<ECDSA_SIG> ecdsa_sig(
      ECDSA_do_sign(digest.data(), digest.size(), private_key_.get()));
  if (ecdsa_sig == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  const BIGNUM *r_bignum;
  const BIGNUM *s_bignum;
  ECDSA_SIG_get0(ecdsa_sig.get(), &r_bignum, &s_bignum);
  if (r_bignum == nullptr || s_bignum == nullptr) {
    return Status(error::GoogleError::INTERNAL, "Could not parse signature");
  }

  std::pair<asylo::Sign, std::vector<uint8_t>> r;
  std::pair<asylo::Sign, std::vector<uint8_t>> s;
  ASYLO_ASSIGN_OR_RETURN(
      r, PaddedBigEndianBytesFromBignum(*r_bignum, kSignatureParamSize));
  ASYLO_ASSIGN_OR_RETURN(
      s, PaddedBigEndianBytesFromBignum(*s_bignum, kSignatureParamSize));
  if (r.first == asylo::Sign::kNegative || s.first == asylo::Sign::kNegative) {
    return Status(error::GoogleError::INTERNAL,
                  "Neither R nor S should be negative");
  }

  EcdsaSignature ecdsa_signature;
  ecdsa_signature.set_r(r.second.data(), r.second.size());
  ecdsa_signature.set_s(s.second.data(), s.second.size());

  signature->set_signature_scheme(GetSignatureScheme());
  *signature->mutable_ecdsa_signature() = std::move(ecdsa_signature);
  return Status::OkStatus();
}

Status EcdsaP256Sha256SigningKey::SignX509(X509 *x509) const {
  bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
  if (EVP_PKEY_set1_EC_KEY(evp_pkey.get(), private_key_.get()) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  if (X509_sign(x509, evp_pkey.get(), EVP_sha256()) == 0) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  return Status::OkStatus();
}

StatusOr<EccP256CurvePoint> EcdsaP256Sha256SigningKey::GetPublicKeyPoint()
    const {
  EccP256CurvePoint public_key;
  const EC_POINT *point = EC_KEY_get0_public_key(private_key_.get());
  const EC_GROUP *group = EC_KEY_get0_group(private_key_.get());

  bssl::UniquePtr<BIGNUM> bignum_x(BN_new());
  bssl::UniquePtr<BIGNUM> bignum_y(BN_new());

  if (EC_POINT_get_affine_coordinates_GFp(
          group, point, bignum_x.get(), bignum_y.get(), /*ctx=*/nullptr) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  ASYLO_ASSIGN_OR_RETURN(public_key.x, ToCoordinate(*bignum_x));
  ASYLO_ASSIGN_OR_RETURN(public_key.y, ToCoordinate(*bignum_y));
  return public_key;
}

EcdsaP256Sha256SigningKey::EcdsaP256Sha256SigningKey(
    bssl::UniquePtr<EC_KEY> private_key, bssl::UniquePtr<EC_KEY> public_key)
    : private_key_(std::move(private_key)),
      public_key_(std::move(public_key)) {}

}  // namespace asylo
