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

#include "asylo/crypto/asn1.h"

#include <openssl/bn.h>
#include <openssl/obj.h>

#include <memory>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/bignum_util.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/util/logging.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

// Converts an OpenSSL ASN.1 type code to an Asn1Type. Returns absl::nullopt if
// the type is unrecognized or not supported.
absl::optional<Asn1Type> FromOpensslType(int openssl_type) {
  switch (openssl_type) {
    case V_ASN1_BOOLEAN:
      return Asn1Type::kBoolean;
    case V_ASN1_INTEGER:
      return Asn1Type::kInteger;
    case V_ASN1_ENUMERATED:
      return Asn1Type::kEnumerated;
    case V_ASN1_OCTET_STRING:
      return Asn1Type::kOctetString;
    case V_ASN1_OBJECT:
      return Asn1Type::kObjectId;
    case V_ASN1_SEQUENCE:
      return Asn1Type::kSequence;
    default:
      return absl::nullopt;
  }
}

// Converts an Asn1Type to an OpenSSL ASN.1 type code.
int ToOpensslType(Asn1Type type) {
  switch (type) {
    case Asn1Type::kBoolean:
      return V_ASN1_BOOLEAN;
    case Asn1Type::kInteger:
      return V_ASN1_INTEGER;
    case Asn1Type::kEnumerated:
      return V_ASN1_ENUMERATED;
    case Asn1Type::kOctetString:
      return V_ASN1_OCTET_STRING;
    case Asn1Type::kObjectId:
      return V_ASN1_OBJECT;
    case Asn1Type::kSequence:
      return V_ASN1_SEQUENCE;
  }

  // GCC 4.9 requires this unreachable return statement.
  return 0;
}

// Returns the name of the type corresponding to the OpenSSL ASN.1 type code
// |openssl_type|. If |openssl_type| is not known, then OpensslTypeName()
// returns "(unknown/unsupported type ##)", where ## is the raw integer value
// of |openssl_type|.
//
// This function supports all universal tag types, not just those supported by
// Asn1Value.
std::string OpensslTypeName(int openssl_type) {
  switch (openssl_type) {
    case V_ASN1_BOOLEAN:
      return "BOOLEAN";
    case V_ASN1_INTEGER:
      ABSL_FALLTHROUGH_INTENDED;
    case V_ASN1_NEG_INTEGER:
      return "INTEGER";
    case V_ASN1_OCTET_STRING:
      return "OCTET STRING";
    case V_ASN1_NULL:
      return "NULL";
    case V_ASN1_OBJECT:
      return "OBJECT IDENTIFIER";
    case V_ASN1_OBJECT_DESCRIPTOR:
      return "ObjectDescriptor";
    case V_ASN1_EXTERNAL:
      return "EXTERNAL";
    case V_ASN1_REAL:
      return "REAL";
    case V_ASN1_ENUMERATED:
      ABSL_FALLTHROUGH_INTENDED;
    case V_ASN1_NEG_ENUMERATED:
      return "ENUMERATED";
    case V_ASN1_UTF8STRING:
      return "UTF8String";
    case V_ASN1_SEQUENCE:
      return "SEQUENCE/SEQUENCE OF";
    case V_ASN1_SET:
      return "SET/SET OF";
    case V_ASN1_NUMERICSTRING:
      return "NumericString";
    case V_ASN1_PRINTABLESTRING:
      return "PrintableString";
    case V_ASN1_T61STRING:
      return "TeletexString/T61String";
    case V_ASN1_VIDEOTEXSTRING:
      return "VideotexString";
    case V_ASN1_IA5STRING:
      return "IA5String";
    case V_ASN1_UTCTIME:
      return "UTCTime";
    case V_ASN1_GENERALIZEDTIME:
      return "GeneralizedTime";
    case V_ASN1_GRAPHICSTRING:
      return "GraphicString";
    case V_ASN1_VISIBLESTRING:
      return "VisibleString/ISO64String";
    case V_ASN1_GENERALSTRING:
      return "GeneralString";
    case V_ASN1_UNIVERSALSTRING:
      return "UniversalString";
    case V_ASN1_BMPSTRING:
      return "BMPString";
    default:
      return absl::StrFormat("(unknown/unsupported type %d)", openssl_type);
  }
}

// Returns a copy of |asn1|. This function uses CHECK()s instead of returning a
// StatusOr<> because it is only used in the copy constructor and
// copy-assignment operator of Asn1Value, which cannot return Statuses.
bssl::UniquePtr<ASN1_TYPE> Asn1TypeCopy(const ASN1_TYPE *asn1) {
  if (asn1 == nullptr) {
    return nullptr;
  }
  bssl::UniquePtr<ASN1_TYPE> result(ASN1_TYPE_new());
  CHECK_EQ(ASN1_TYPE_set1(result.get(), asn1->type, asn1->value.ptr), 1)
      << BsslLastErrorString();
  return result;
}

}  // namespace

Asn1Value::Asn1Value() : value_(ASN1_TYPE_new()) {}

Asn1Value::Asn1Value(const Asn1Value &other)
    : value_(Asn1TypeCopy(other.value_.get())) {}

Asn1Value &Asn1Value::operator=(const Asn1Value &other) {
  value_ = Asn1TypeCopy(other.value_.get());
  return *this;
}

Asn1Value::Asn1Value(Asn1Value &&other) : value_(std::move(other.value_)) {
  other.value_.reset(ASN1_TYPE_new());
}

Asn1Value &Asn1Value::operator=(Asn1Value &&other) {
  value_ = std::move(other.value_);
  other.value_.reset(ASN1_TYPE_new());
  return *this;
}

StatusOr<Asn1Value> Asn1Value::CreateBoolean(bool value) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetBoolean(value));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateInteger(const BIGNUM &value) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetInteger(value));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateIntegerFromInt64(int64_t value) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetIntegerFromInt64(value));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateEnumerated(const BIGNUM &value) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetEnumerated(value));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateEnumeratedFromInt64(int64_t value) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetEnumeratedFromInt64(value));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateOctetString(ByteContainerView value) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetOctetString(value));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateObjectId(const std::string &oid_string) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetObjectId(oid_string));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateSequence(
    absl::Span<const Asn1Value> elements) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetSequence(elements));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateFromDer(ByteContainerView asn1_der) {
  const uint8_t *der_data = asn1_der.data();
  bssl::UniquePtr<ASN1_TYPE> asn1(
      d2i_ASN1_TYPE(/*a=*/nullptr, &der_data, asn1_der.size()));
  if (asn1 == nullptr) {
    return Status(error::GoogleError::INVALID_ARGUMENT, BsslLastErrorString());
  }
  return Asn1Value(std::move(asn1));
}

absl::optional<Asn1Type> Asn1Value::Type() const {
  return value_ != nullptr ? FromOpensslType(value_->type) : absl::nullopt;
}

StatusOr<bool> Asn1Value::GetBoolean() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kBoolean));
  return value_->value.boolean;
}

StatusOr<bssl::UniquePtr<BIGNUM>> Asn1Value::GetInteger() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kInteger));
  bssl::UniquePtr<BIGNUM> result(
      ASN1_INTEGER_to_BN(value_->value.integer, /*bn=*/nullptr));
  if (result == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  // GCC 4.9 requires this std::move() invocation.
  return std::move(result);
}

StatusOr<int64_t> Asn1Value::GetIntegerAsInt64() const {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSIGN_OR_RETURN(bignum, GetInteger());
  return IntegerFromBignum(*bignum);
}

StatusOr<bssl::UniquePtr<BIGNUM>> Asn1Value::GetEnumerated() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kEnumerated));
  bssl::UniquePtr<BIGNUM> result(
      ASN1_ENUMERATED_to_BN(value_->value.enumerated, /*bn=*/nullptr));
  if (result == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  // GCC 4.9 requires this std::move() invocation.
  return std::move(result);
}

StatusOr<int64_t> Asn1Value::GetEnumeratedAsInt64() const {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSIGN_OR_RETURN(bignum, GetEnumerated());
  return IntegerFromBignum(*bignum);
}

StatusOr<std::vector<uint8_t>> Asn1Value::GetOctetString() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kOctetString));
  const ASN1_OCTET_STRING *string = value_->value.octet_string;
  ByteContainerView string_data_view(ASN1_STRING_get0_data(string),
                                     ASN1_STRING_length(string));
  return std::vector<uint8_t>(string_data_view.begin(), string_data_view.end());
}

StatusOr<std::string> Asn1Value::GetObjectId() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kObjectId));
  const ASN1_OBJECT *oid = value_->value.object;
  char buf;
  int length = OBJ_obj2txt(&buf, 0, oid, /*always_return_oid=*/1);
  if (length < 0) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  std::vector<char> oid_string(length + 1);
  int length2 = OBJ_obj2txt(oid_string.data(), oid_string.size(), oid,
                            /*always_return_oid=*/1);
  if (length2 != length) {
    if (length2 >= 0) {
      return Status(error::GoogleError::INTERNAL,
                    "OBJECT IDENTIFIER length changed unexpectedly");
    } else {
      return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
    }
  }
  return std::string(oid_string.data());
}

StatusOr<std::vector<Asn1Value>> Asn1Value::GetSequence() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kSequence));
  const ASN1_STRING *der_string = value_->value.sequence;
  const unsigned char *der_data = ASN1_STRING_get0_data(der_string);
  bssl::UniquePtr<ASN1_SEQUENCE_ANY> sequence(d2i_ASN1_SEQUENCE_ANY(
      /*a=*/nullptr, &der_data, ASN1_STRING_length(der_string)));
  if (sequence == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  int sequence_length = sk_ASN1_TYPE_num(sequence.get());
  std::vector<Asn1Value> result(sequence_length);
  for (int i = sequence_length - 1; i >= 0; --i) {
    bssl::UniquePtr<ASN1_TYPE> element(sk_ASN1_TYPE_pop(sequence.get()));
    if (element == nullptr) {
      return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
    }
    result[i] = Asn1Value(std::move(element));
  }
  return result;
}

Status Asn1Value::SetBoolean(bool value) {
  // A non-null pointer. Used when calling ASN1_TYPE_set() with V_ASN1_BOOLEAN.
  void *const kNonNullPointer = reinterpret_cast<void *>(true);

  ASN1_TYPE_set(value_.get(), V_ASN1_BOOLEAN,
                value ? kNonNullPointer : nullptr);
  return Status::OkStatus();
}

Status Asn1Value::SetInteger(const BIGNUM &value) {
  bssl::UniquePtr<ASN1_INTEGER> value_asn1_integer(
      BN_to_ASN1_INTEGER(&value, /*ai=*/nullptr));
  if (value_asn1_integer == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  ASN1_TYPE_set(value_.get(), V_ASN1_INTEGER, value_asn1_integer.release());
  return Status::OkStatus();
}

Status Asn1Value::SetIntegerFromInt64(int64_t value) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSIGN_OR_RETURN(bignum, BignumFromInteger(value));
  return SetInteger(*bignum);
}

Status Asn1Value::SetEnumerated(const BIGNUM &value) {
  bssl::UniquePtr<ASN1_ENUMERATED> value_asn1_enumerated(
      BN_to_ASN1_ENUMERATED(const_cast<BIGNUM *>(&value), /*ai=*/nullptr));
  if (value_asn1_enumerated == nullptr) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  ASN1_TYPE_set(value_.get(), V_ASN1_ENUMERATED,
                value_asn1_enumerated.release());
  return Status::OkStatus();
}

Status Asn1Value::SetEnumeratedFromInt64(int64_t value) {
  bssl::UniquePtr<BIGNUM> bignum;
  ASYLO_ASSIGN_OR_RETURN(bignum, BignumFromInteger(value));
  return SetEnumerated(*bignum);
}

Status Asn1Value::SetOctetString(ByteContainerView value) {
  bssl::UniquePtr<ASN1_OCTET_STRING> value_octet_string(
      ASN1_OCTET_STRING_new());
  if (ASN1_STRING_set(value_octet_string.get(), value.data(), value.size()) !=
      1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  ASN1_TYPE_set(value_.get(), V_ASN1_OCTET_STRING,
                value_octet_string.release());
  return Status::OkStatus();
}

Status Asn1Value::SetObjectId(const std::string &oid_string) {
  bssl::UniquePtr<ASN1_OBJECT> oid(
      OBJ_txt2obj(oid_string.c_str(), /*dont_search_names=*/1));
  if (oid == nullptr) {
    return Status(error::GoogleError::INVALID_ARGUMENT, BsslLastErrorString());
  }

  ASN1_TYPE_set(value_.get(), V_ASN1_OBJECT, oid.release());
  return Status::OkStatus();
}

Status Asn1Value::SetSequence(absl::Span<const Asn1Value> elements) {
  bssl::UniquePtr<ASN1_SEQUENCE_ANY> sequence(sk_ASN1_TYPE_new_null());
  for (const Asn1Value &element : elements) {
    if (sk_ASN1_TYPE_push(sequence.get(),
                          Asn1TypeCopy(element.value_.get()).release()) == 0) {
      return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
    }
  }

  unsigned char *der_unowned = nullptr;
  int der_length = i2d_ASN1_SEQUENCE_ANY(sequence.get(), &der_unowned);
  if (der_length < 0) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  bssl::UniquePtr<unsigned char> der(der_unowned);

  bssl::UniquePtr<ASN1_STRING> der_string(
      ASN1_STRING_type_new(V_ASN1_SEQUENCE));
  if (ASN1_STRING_set(der_string.get(), der.get(), der_length) != 1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }

  ASN1_TYPE_set(value_.get(), V_ASN1_SEQUENCE, der_string.release());
  return Status::OkStatus();
}

StatusOr<std::vector<uint8_t>> Asn1Value::SerializeToDer() const {
  if (value_ == nullptr) {
    return Status(error::GoogleError::INVALID_ARGUMENT, "Asn1Value is empty");
  }

  unsigned char *der_unowned = nullptr;
  int der_length = i2d_ASN1_TYPE(value_.get(), &der_unowned);
  if (der_length == -1) {
    return Status(error::GoogleError::INTERNAL, BsslLastErrorString());
  }
  bssl::UniquePtr<unsigned char> der(der_unowned);
  ByteContainerView der_view(der.get(), der_length);
  std::vector<uint8_t> result(der_view.begin(), der_view.end());
  return result;
}

Asn1Value::Asn1Value(bssl::UniquePtr<ASN1_TYPE> value)
    : value_(std::move(value)) {}

Status Asn1Value::CheckIsType(Asn1Type type) const {
  if (value_ == nullptr) {
    return Status(error::GoogleError::INVALID_ARGUMENT, "Asn1Value is empty");
  }

  int openssl_type = ToOpensslType(type);
  if (value_->type != openssl_type) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrFormat("Asn1Value is a %s, not a %s",
                                  OpensslTypeName(value_->type),
                                  OpensslTypeName(openssl_type)));
  }

  return Status::OkStatus();
}

bool operator==(const Asn1Value &lhs, const Asn1Value &rhs) {
  // The ASN1_TYPE_cmp() function doesn't compare INTEGER or ENUMERATED values
  // properly. (It treats a single zero-byte as different from an empty byte
  // sequence.) As such, the comparison logic is implemented correctly here.

  if (lhs.value_->type != rhs.value_->type) {
    return false;
  }

  auto maybe_type = lhs.Type();
  if (!maybe_type.has_value()) {
    return false;
  }
  switch (maybe_type.value()) {
    case Asn1Type::kInteger:
      return BN_cmp(lhs.GetInteger().ValueOrDie().get(),
                    rhs.GetInteger().ValueOrDie().get()) == 0;
    case Asn1Type::kEnumerated:
      return BN_cmp(lhs.GetEnumerated().ValueOrDie().get(),
                    rhs.GetEnumerated().ValueOrDie().get()) == 0;
    case Asn1Type::kSequence:
      return lhs.GetSequence().ValueOrDie() == rhs.GetSequence().ValueOrDie();
    case Asn1Type::kBoolean:
      ABSL_FALLTHROUGH_INTENDED;
    case Asn1Type::kObjectId:
      ABSL_FALLTHROUGH_INTENDED;
    case Asn1Type::kOctetString:
      return ASN1_TYPE_cmp(lhs.value_.get(), rhs.value_.get()) == 0;
  }

  // GCC 4.9 requires this unreachable return statement.
  return false;
}

bool operator!=(const Asn1Value &lhs, const Asn1Value &rhs) {
  return !(lhs == rhs);
}

}  // namespace asylo