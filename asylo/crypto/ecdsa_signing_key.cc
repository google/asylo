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

#include "asylo/crypto/ecdsa_signing_key.h"

#include <openssl/base.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace internal {

// Returns an EC_KEY containing the public key corresponding to |private_key|.
StatusOr<bssl::UniquePtr<EC_KEY>> CreatePublicKeyFromPrivateKey(
    EC_KEY *private_key, int nid) {
  bssl::UniquePtr<EC_KEY> public_key(EC_KEY_new_by_curve_name(nid));
  if (!public_key) {
    return Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Error creating public key: ", BsslLastErrorString()));
  }
  if (EC_KEY_get0_public_key(private_key) == nullptr) {
    bssl::UniquePtr<EC_POINT> key_point(
        EC_POINT_new(EC_KEY_get0_group(private_key)));
    if (!EC_POINT_mul(EC_KEY_get0_group(private_key), key_point.get(),
                      EC_KEY_get0_private_key(private_key), /*q=*/nullptr,
                      /*m=*/nullptr, /*ctx=*/nullptr)) {
      return Status(
          absl::StatusCode::kInternal,
          absl::StrCat("Error computing public key: ", BsslLastErrorString()));
    }
    if (!EC_KEY_set_public_key(private_key, key_point.get())) {
      return Status(absl::StatusCode::kInternal,
                    absl::StrCat("Error setting computed public key: ",
                                 BsslLastErrorString()));
    }
  }
  if (!EC_KEY_set_public_key(public_key.get(),
                             EC_KEY_get0_public_key(private_key))) {
    return Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Error setting public key: ", BsslLastErrorString()));
  }

  return std::move(public_key);
}

Status CheckKeyProtoValues(const AsymmetricSigningKeyProto &key_proto,
                           AsymmetricSigningKeyProto::KeyType expected_type,
                           SignatureScheme signature_scheme) {
  if (key_proto.key_type() != expected_type) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Key type of the key (%s) does not match the expected "
                        "key type (%s)",
                        ProtoEnumValueName(key_proto.key_type()),
                        ProtoEnumValueName(expected_type)));
  }

  if (key_proto.signature_scheme() != signature_scheme) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Signature scheme of the key (%s) does not match the "
                        "expected signature scheme (%s)",
                        ProtoEnumValueName(key_proto.signature_scheme()),
                        ProtoEnumValueName(signature_scheme)));
  }
  return absl::OkStatus();
}

StatusOr<bssl::UniquePtr<EC_KEY>> GetPublicEcKeyFromDer(
    ByteContainerView serialized_key) {
  // The input data containing the serialized public key.
  uint8_t const *serialized_key_data = serialized_key.data();

  // Create a public key from the input data. If |a| was set, the EC_KEY object
  // referenced by |a| would be freed and |a| would be updated to point to the
  // returned object.
  bssl::UniquePtr<EC_KEY> key(d2i_EC_PUBKEY(
      /*out=*/nullptr, &serialized_key_data, serialized_key.size()));
  if (!key) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::move(key);
}

StatusOr<bssl::UniquePtr<EC_KEY>> GetPublicEcKeyFromPem(
    ByteContainerView serialized_key) {
  // The input bio object containing the serialized public key.
  bssl::UniquePtr<BIO> key_bio(
      BIO_new_mem_buf(serialized_key.data(), serialized_key.size()));

  // Create a public key from the input PEM data. For more information, see
  // https://www.openssl.org/docs/man1.1.0/man3/PEM_read_bio_EC_PUBKEY.html.
  bssl::UniquePtr<EC_KEY> key(PEM_read_bio_EC_PUBKEY(
      key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));
  if (!key) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::move(key);
}

StatusOr<bssl::UniquePtr<EC_KEY>> GetPublicEcKeyFromCurvePoint(
    int nid, const BIGNUM *x, const BIGNUM *y) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(nid));
  if (key == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group));
  if (EC_POINT_set_affine_coordinates_GFp(group, point.get(), x, y,
                                          /*ctx=*/nullptr) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  if (EC_KEY_set_public_key(key.get(), point.get()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::move(key);
}

int GetEcCurveNid(const EC_KEY *key) {
  return EC_GROUP_get_curve_name(EC_KEY_get0_group(key));
}

bool PublicKeyCompare(const EC_KEY *key1, const EC_KEY *key2) {
  const EC_GROUP *group = EC_KEY_get0_group(key1);
  const EC_GROUP *other_group = EC_KEY_get0_group(key2);

  const EC_POINT *point = EC_KEY_get0_public_key(key1);
  const EC_POINT *other_point = EC_KEY_get0_public_key(key2);

  return (EC_GROUP_cmp(group, other_group, /*ignored=*/nullptr) == 0) &&
         (EC_POINT_cmp(group, point, other_point, /*ctx=*/nullptr) == 0);
}

StatusOr<std::string> BsslSerializePublicKeyToDer(const EC_KEY *public_key) {
  uint8_t *key = nullptr;
  int length = i2d_EC_PUBKEY(public_key, &key);
  if (length <= 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  bssl::UniquePtr<uint8_t> deleter(key);
  return std::string(reinterpret_cast<char *>(key), length);
}

StatusOr<std::string> BsslSerializePublicKeyToPem(EC_KEY *public_key) {
  bssl::UniquePtr<BIO> key_bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_EC_PUBKEY(key_bio.get(), public_key)) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  size_t key_data_size;
  const uint8_t *key_data = nullptr;
  if (BIO_mem_contents(key_bio.get(), &key_data, &key_data_size) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::string(reinterpret_cast<const char *>(key_data), key_data_size);
}

Status VerifyEcdsa(ByteContainerView digest, ByteContainerView signature,
                   const EC_KEY *public_key) {
  if (ECDSA_verify(/*type=*/0, digest.data(), digest.size(), signature.data(),
                   signature.size(), public_key) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return absl::OkStatus();
}

Status VerifyEcdsaWithRS(ByteContainerView r, ByteContainerView s,
                         ByteContainerView digest, const EC_KEY *public_key) {
  bssl::UniquePtr<BIGNUM> r_bignum;
  ASYLO_ASSIGN_OR_RETURN(r_bignum, BignumFromBigEndianBytes(r));
  bssl::UniquePtr<BIGNUM> s_bignum;
  ASYLO_ASSIGN_OR_RETURN(s_bignum, BignumFromBigEndianBytes(s));

  bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_new());
  if (ECDSA_SIG_set0(sig.get(), r_bignum.release(), s_bignum.release()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  if (ECDSA_do_verify(digest.data(), digest.size(), sig.get(), public_key) !=
      1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return absl::OkStatus();
}

StatusOr<bssl::UniquePtr<EC_KEY>> CreatePrivateEcKey(int nid) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(nid));
  if (!key) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  int result = 0;
  if (FIPS_mode()) {
    result = EC_KEY_generate_key_fips(key.get());
  } else {
    result = EC_KEY_generate_key(key.get());
  }
  if (!result) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::move(key);
}

StatusOr<bssl::UniquePtr<EC_KEY>> CreatePrivateEcKeyFromDer(
    int nid, ByteContainerView serialized_key) {
  CBS buffer;
  CBS_init(&buffer, serialized_key.data(), serialized_key.size());

  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(nid));
  if (!group) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_parse_private_key(&buffer, group.get()));
  if (!key) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::move(key);
}

StatusOr<bssl::UniquePtr<EC_KEY>> CreatePrivateEcKeyFromPem(
    ByteContainerView serialized_key) {
  // The input bio object containing the serialized public key.
  bssl::UniquePtr<BIO> key_bio(
      BIO_new_mem_buf(serialized_key.data(), serialized_key.size()));

  // Create a private key from the input PEM data.
  bssl::UniquePtr<EC_KEY> key(PEM_read_bio_ECPrivateKey(
      key_bio.get(), /*x=*/nullptr, /*cb=*/nullptr, /*u=*/nullptr));
  if (!key) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::move(key);
}

StatusOr<bssl::UniquePtr<EC_KEY>> CreatePrivateEcKeyFromScalar(
    int nid, const BIGNUM *scalar) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(nid));
  if (!key) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  if (!EC_KEY_set_private_key(key.get(), scalar)) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::move(key);
}

StatusOr<CleansingVector<uint8_t>> BsslSerializePrivateKeyToDer(
    const EC_KEY *private_key) {
  CBB buffer;
  if (!CBB_init(&buffer, /*initial_capacity=*/0) ||
      !EC_KEY_marshal_private_key(&buffer, private_key,
                                  EC_KEY_get_enc_flags(private_key))) {
    CBB_cleanup(&buffer);
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  uint8_t *key_data;
  size_t key_data_size = 0;
  CBB_finish(&buffer, &key_data, &key_data_size);

  CleansingVector<uint8_t> serialized_key(key_data, key_data + key_data_size);

  OPENSSL_cleanse(key_data, key_data_size);
  OPENSSL_free(key_data);

  return serialized_key;
}

StatusOr<CleansingVector<char>> BsslSerializePrivateKeyToPem(
    EC_KEY *private_key) {
  bssl::UniquePtr<BIO> key_bio(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_ECPrivateKey(key_bio.get(), private_key,
                                  /*enc=*/nullptr, /*kstr=*/nullptr, /*klen=*/0,
                                  /*cb=*/nullptr, /*u=*/nullptr)) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  size_t key_data_size;
  const uint8_t *key_data = nullptr;
  if (BIO_mem_contents(key_bio.get(), &key_data, &key_data_size) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return CleansingVector<char>(key_data, key_data + key_data_size);
}

StatusOr<bssl::UniquePtr<EC_KEY>> GetPublicEcKey(const EC_KEY *public_key) {
  bssl::UniquePtr<EC_KEY> public_key_copy(EC_KEY_dup(public_key));
  if (!public_key_copy) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::move(public_key_copy);
}

Status EcdsaSign(std::vector<uint8_t> *signature, ByteContainerView digest,
                 const EC_KEY *private_key) {
  signature->resize(ECDSA_size(private_key));
  uint32_t signature_size = 0;
  if (!ECDSA_sign(/*type=*/0, digest.data(), digest.size(), signature->data(),
                  &signature_size, private_key)) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  signature->resize(signature_size);
  return absl::OkStatus();
}

Status EcdsaSignDigestAndSetRS(SignatureScheme sig_scheme,
                               ByteContainerView digest,
                               const EC_KEY *private_key,
                               int32_t coordinate_size, Signature *signature) {
  bssl::UniquePtr<ECDSA_SIG> ecdsa_sig(
      ECDSA_do_sign(digest.data(), digest.size(), private_key));
  if (ecdsa_sig == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  const BIGNUM *r_bignum;
  const BIGNUM *s_bignum;
  ECDSA_SIG_get0(ecdsa_sig.get(), &r_bignum, &s_bignum);
  if (r_bignum == nullptr || s_bignum == nullptr) {
    return Status(absl::StatusCode::kInternal, "Could not parse signature");
  }

  std::pair<asylo::Sign, std::vector<uint8_t>> r;
  std::pair<asylo::Sign, std::vector<uint8_t>> s;
  ASYLO_ASSIGN_OR_RETURN(
      r, PaddedBigEndianBytesFromBignum(*r_bignum, coordinate_size));
  ASYLO_ASSIGN_OR_RETURN(
      s, PaddedBigEndianBytesFromBignum(*s_bignum, coordinate_size));
  if (r.first == asylo::Sign::kNegative || s.first == asylo::Sign::kNegative) {
    return Status(absl::StatusCode::kInternal,
                  "Neither R nor S should be negative");
  }

  EcdsaSignature ecdsa_signature;
  ecdsa_signature.set_r(r.second.data(), r.second.size());
  ecdsa_signature.set_s(s.second.data(), s.second.size());

  signature->set_signature_scheme(sig_scheme);
  *signature->mutable_ecdsa_signature() = std::move(ecdsa_signature);

  return absl::OkStatus();
}

StatusOr<std::pair<bssl::UniquePtr<BIGNUM>, bssl::UniquePtr<BIGNUM>>>
GetEcdsaPoint(const EC_KEY *private_key) {
  const EC_POINT *point = EC_KEY_get0_public_key(private_key);
  const EC_GROUP *group = EC_KEY_get0_group(private_key);

  bssl::UniquePtr<BIGNUM> bignum_x(BN_new());
  bssl::UniquePtr<BIGNUM> bignum_y(BN_new());

  if (EC_POINT_get_affine_coordinates_GFp(
          group, point, bignum_x.get(), bignum_y.get(), /*ctx=*/nullptr) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  return std::make_pair(std::move(bignum_x), std::move(bignum_y));
}

}  // namespace internal
}  // namespace asylo
