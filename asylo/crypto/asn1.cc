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

#include <openssl/asn1.h>
#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/obj.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/macros.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/logging.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

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
    case V_ASN1_BIT_STRING:
      return Asn1Type::kBitString;
    case V_ASN1_OCTET_STRING:
      return Asn1Type::kOctetString;
    case V_ASN1_OBJECT:
      return Asn1Type::kObjectId;
    case V_ASN1_SEQUENCE:
      return Asn1Type::kSequence;
    case V_ASN1_IA5STRING:
      return Asn1Type::kIA5String;
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
    case Asn1Type::kBitString:
      return V_ASN1_BIT_STRING;
    case Asn1Type::kOctetString:
      return V_ASN1_OCTET_STRING;
    case Asn1Type::kObjectId:
      return V_ASN1_OBJECT;
    case Asn1Type::kSequence:
      return V_ASN1_SEQUENCE;
    case Asn1Type::kIA5String:
      return V_ASN1_IA5STRING;
  }

  return V_ASN1_UNDEF;
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
    case V_ASN1_BIT_STRING:
      return "BIT STRING";
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

// Returns a copy of |object|. This function uses CHECK()s instead of returning
// a StatusOr<> because it is only used in the copy constructor and
// copy-assignment operator of ObjectId, which cannot return Statuses. In
// addition, the only possible failure mode is an out-of-memory failure.
bssl::UniquePtr<ASN1_OBJECT> Asn1ObjectCopy(const ASN1_OBJECT *object) {
  if (object == nullptr) {
    return nullptr;
  }
  return bssl::UniquePtr<ASN1_OBJECT>(CHECK_NOTNULL(OBJ_dup(object)));
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

ObjectId::ObjectId(const ObjectId &other)
    : object_(Asn1ObjectCopy(other.object_.get())) {}

ObjectId &ObjectId::operator=(const ObjectId &other) {
  object_ = Asn1ObjectCopy(other.object_.get());
  return *this;
}

StatusOr<ObjectId> ObjectId::CreateFromShortName(
    const std::string &short_name) {
  int nid = OBJ_sn2nid(short_name.c_str());
  if (nid == NID_undef) {
    return Status(absl::StatusCode::kNotFound,
                  absl::StrFormat("No OBJECT IDENTIFIER with short name \"%s\"",
                                  short_name));
  }
  return CreateFromNumericId(nid);
}

StatusOr<ObjectId> ObjectId::CreateFromLongName(const std::string &long_name) {
  int nid = OBJ_ln2nid(long_name.c_str());
  if (nid == NID_undef) {
    return Status(absl::StatusCode::kNotFound,
                  absl::StrFormat("No OBJECT IDENTIFIER with long name \"%s\"",
                                  long_name));
  }
  return CreateFromNumericId(nid);
}

StatusOr<ObjectId> ObjectId::CreateFromNumericId(int nid) {
  const ASN1_OBJECT *object_original = OBJ_nid2obj(nid);
  if (object_original == nullptr) {
    return Status(absl::StatusCode::kNotFound,
                  absl::StrCat("No OBJECT IDENTIFIER with NID ", nid));
  }
  bssl::UniquePtr<ASN1_OBJECT> object(OBJ_dup(object_original));
  if (object == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return ObjectId(std::move(object));
}

StatusOr<ObjectId> ObjectId::CreateFromOidString(
    const std::string &oid_string) {
  bssl::UniquePtr<ASN1_OBJECT> oid(
      OBJ_txt2obj(oid_string.c_str(), /*dont_search_names=*/1));
  if (oid == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return ObjectId(std::move(oid));
}

StatusOr<ObjectId> ObjectId::CreateFromBsslObject(const ASN1_OBJECT &bssl) {
  bssl::UniquePtr<ASN1_OBJECT> object(OBJ_dup(&bssl));
  if (object == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return ObjectId(std::move(object));
}

StatusOr<std::string> ObjectId::GetShortName() const {
  int nid;
  ASYLO_ASSIGN_OR_RETURN(nid, GetNumericId());
  const char *short_name = OBJ_nid2sn(nid);
  if (short_name == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return short_name;
}

StatusOr<std::string> ObjectId::GetLongName() const {
  int nid;
  ASYLO_ASSIGN_OR_RETURN(nid, GetNumericId());
  const char *long_name = OBJ_nid2ln(nid);
  if (long_name == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return long_name;
}

StatusOr<int> ObjectId::GetNumericId() const {
  int nid = OBJ_obj2nid(object_.get());
  if (nid == NID_undef) {
    return Status(absl::StatusCode::kNotFound,
                  "OBJECT_IDENTIFIER does not have an NID");
  }
  return nid;
}

StatusOr<std::string> ObjectId::GetOidString() const {
  char buf;
  int length = OBJ_obj2txt(&buf, /*out_len=*/0, object_.get(),
                           /*always_return_oid=*/1);
  if (length < 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  std::vector<char> oid_string(length + 1);
  int length2 = OBJ_obj2txt(oid_string.data(), oid_string.size(), object_.get(),
                            /*always_return_oid=*/1);
  if (length2 != length) {
    if (length2 >= 0) {
      return Status(absl::StatusCode::kInternal,
                    "OBJECT IDENTIFIER length changed unexpectedly");
    } else {
      return Status(absl::StatusCode::kInternal, BsslLastErrorString());
    }
  }
  return std::string(oid_string.data());
}

const ASN1_OBJECT &ObjectId::GetBsslObject() const { return *object_; }

StatusOr<bssl::UniquePtr<ASN1_OBJECT>> ObjectId::GetBsslObjectCopy() const {
  bssl::UniquePtr<ASN1_OBJECT> copy(OBJ_dup(object_.get()));
  if (copy == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  // GCC 4.9 requires this std::move() invocation.
  return std::move(copy);
}

ObjectId::ObjectId(bssl::UniquePtr<ASN1_OBJECT> object)
    : object_(std::move(object)) {}

bool operator==(const ObjectId &lhs, const ObjectId &rhs) {
  if (lhs.object_ == nullptr || rhs.object_ == nullptr) {
    return lhs.object_ == rhs.object_;
  }
  return OBJ_cmp(lhs.object_.get(), rhs.object_.get()) == 0;
}

bool operator!=(const ObjectId &lhs, const ObjectId &rhs) {
  return !(lhs == rhs);
}

std::ostream &operator<<(std::ostream &out, const ObjectId &oid) {
  auto short_name_result = oid.GetShortName();
  if (short_name_result.ok()) {
    return out << short_name_result.value();
  }

  auto oid_string_result = oid.GetOidString();
  if (oid_string_result.ok() && !oid_string_result.value().empty()) {
    return out << oid_string_result.value();
  }

  return out << "UNKNOWN_OID";
}

Asn1Value::Asn1Value() : value_(CHECK_NOTNULL(ASN1_TYPE_new())) {}

Asn1Value::Asn1Value(const Asn1Value &other)
    : value_(Asn1TypeCopy(other.value_.get())) {}

Asn1Value &Asn1Value::operator=(const Asn1Value &other) {
  value_ = Asn1TypeCopy(other.value_.get());
  return *this;
}

Asn1Value::Asn1Value(Asn1Value &&other) : value_(std::move(other.value_)) {
  other.value_.reset(CHECK_NOTNULL(ASN1_TYPE_new()));
}

Asn1Value &Asn1Value::operator=(Asn1Value &&other) {
  value_ = std::move(other.value_);
  other.value_.reset(CHECK_NOTNULL(ASN1_TYPE_new()));
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

StatusOr<Asn1Value> Asn1Value::CreateEnumerated(const BIGNUM &value) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetEnumerated(value));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateBitString(const std::vector<bool> &value) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetBitString(value));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateOctetString(ByteContainerView value) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetOctetString(value));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateObjectId(const ObjectId &value) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetObjectId(value));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateSequence(
    absl::Span<const Asn1Value> elements) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetSequence(elements));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateIA5String(absl::string_view value) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetIA5String(value));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateSequenceFromStatusOrs(
    absl::Span<const StatusOr<Asn1Value>> results) {
  Asn1Value result;
  ASYLO_RETURN_IF_ERROR(result.SetSequenceFromStatusOrs(results));
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateFromDer(ByteContainerView asn1_der) {
  const uint8_t *der_data = asn1_der.data();
  bssl::UniquePtr<ASN1_TYPE> asn1(
      d2i_ASN1_TYPE(/*a=*/nullptr, &der_data, asn1_der.size()));
  if (asn1 == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument, BsslLastErrorString());
  }
  return Asn1Value(std::move(asn1));
}

absl::optional<Asn1Type> Asn1Value::Type() const {
  return value_ != nullptr ? FromOpensslType(value_->type) : absl::nullopt;
}

StatusOr<bool> Asn1Value::GetBoolean() const { return GetBsslBoolean(); }

StatusOr<bssl::UniquePtr<BIGNUM>> Asn1Value::GetInteger() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kInteger));
  bssl::UniquePtr<BIGNUM> result(
      ASN1_INTEGER_to_BN(value_->value.integer, /*bn=*/nullptr));
  if (result == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  // GCC 4.9 requires this std::move() invocation.
  return std::move(result);
}

StatusOr<bssl::UniquePtr<BIGNUM>> Asn1Value::GetEnumerated() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kEnumerated));
  bssl::UniquePtr<BIGNUM> result(
      ASN1_ENUMERATED_to_BN(value_->value.enumerated, /*bn=*/nullptr));
  if (result == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  // GCC 4.9 requires this std::move() invocation.
  return std::move(result);
}

StatusOr<std::vector<bool>> Asn1Value::GetBitString() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kBitString));
  // Copy the value because ASN1_BIT_STRING_get_bit() takes a non-const
  // ASN1_BIT_STRING pointer.
  bssl::UniquePtr<ASN1_BIT_STRING> bssl_bit_string(
      CHECK_NOTNULL(ASN1_STRING_dup(value_->value.bit_string)));
  int num_bits_upper_bound = ASN1_STRING_length(bssl_bit_string.get()) * 8;
  std::vector<bool> bits(num_bits_upper_bound, false);
  int highest_bit = -1;
  for (int i = 0; i < num_bits_upper_bound; ++i) {
    if (ASN1_BIT_STRING_get_bit(bssl_bit_string.get(), i)) {
      highest_bit = i;
      bits[i] = true;
    }
  }
  bits.resize(highest_bit + 1);
  return bits;
}

StatusOr<std::vector<uint8_t>> Asn1Value::GetOctetString() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kOctetString));
  const ASN1_OCTET_STRING *string = value_->value.octet_string;
  ByteContainerView string_data_view(ASN1_STRING_get0_data(string),
                                     ASN1_STRING_length(string));
  return std::vector<uint8_t>(string_data_view.begin(), string_data_view.end());
}

StatusOr<ObjectId> Asn1Value::GetObjectId() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kObjectId));
  return ObjectId::CreateFromBsslObject(*value_->value.object);
}

StatusOr<std::vector<Asn1Value>> Asn1Value::GetSequence() const {
  bssl::UniquePtr<ASN1_SEQUENCE_ANY> sequence;
  ASYLO_ASSIGN_OR_RETURN(sequence, GetBsslSequence());
  if (sequence == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  int sequence_length = sk_ASN1_TYPE_num(sequence.get());
  std::vector<Asn1Value> result(sequence_length);
  for (int i = sequence_length - 1; i >= 0; --i) {
    bssl::UniquePtr<ASN1_TYPE> element(sk_ASN1_TYPE_pop(sequence.get()));
    if (element == nullptr) {
      return Status(absl::StatusCode::kInternal, BsslLastErrorString());
    }
    result[i] = Asn1Value(std::move(element));
  }
  return result;
}

StatusOr<std::string> Asn1Value::GetIA5String() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kIA5String));
  const ASN1_IA5STRING *str = value_->value.ia5string;

  return std::string(reinterpret_cast<const char *>(ASN1_STRING_get0_data(str)),
                     ASN1_STRING_length(str));
}

Status Asn1Value::SetBoolean(bool value) { return SetBsslBoolean(value); }

Status Asn1Value::SetInteger(const BIGNUM &value) {
  bssl::UniquePtr<ASN1_INTEGER> value_asn1_integer(
      BN_to_ASN1_INTEGER(&value, /*ai=*/nullptr));
  if (value_asn1_integer == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  ASN1_TYPE_set(value_.get(), V_ASN1_INTEGER, value_asn1_integer.release());
  return absl::OkStatus();
}

Status Asn1Value::SetEnumerated(const BIGNUM &value) {
  bssl::UniquePtr<ASN1_ENUMERATED> value_asn1_enumerated(
      BN_to_ASN1_ENUMERATED(const_cast<BIGNUM *>(&value), /*ai=*/nullptr));
  if (value_asn1_enumerated == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  ASN1_TYPE_set(value_.get(), V_ASN1_ENUMERATED,
                value_asn1_enumerated.release());
  return absl::OkStatus();
}

Status Asn1Value::SetBitString(const std::vector<bool> &value) {
  bssl::UniquePtr<ASN1_BIT_STRING> bssl_bit_string(
      CHECK_NOTNULL(ASN1_BIT_STRING_new()));
  for (int i = 0; i < value.size(); ++i) {
    if (ASN1_BIT_STRING_set_bit(bssl_bit_string.get(), i, value[i]) != 1) {
      return Status(absl::StatusCode::kInternal, BsslLastErrorString());
    }
  }

  ASN1_TYPE_set(value_.get(), V_ASN1_BIT_STRING, bssl_bit_string.release());
  return absl::OkStatus();
}

Status Asn1Value::SetOctetString(ByteContainerView value) {
  bssl::UniquePtr<ASN1_OCTET_STRING> value_octet_string(
      ASN1_OCTET_STRING_new());
  if (ASN1_STRING_set(value_octet_string.get(), value.data(), value.size()) !=
      1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  ASN1_TYPE_set(value_.get(), V_ASN1_OCTET_STRING,
                value_octet_string.release());
  return absl::OkStatus();
}

Status Asn1Value::SetObjectId(const ObjectId &value) {
  bssl::UniquePtr<ASN1_OBJECT> object;
  ASYLO_ASSIGN_OR_RETURN(object, value.GetBsslObjectCopy());
  ASN1_TYPE_set(value_.get(), V_ASN1_OBJECT, object.release());
  return absl::OkStatus();
}

Status Asn1Value::SetSequence(absl::Span<const Asn1Value> elements) {
  bssl::UniquePtr<ASN1_SEQUENCE_ANY> sequence(sk_ASN1_TYPE_new_null());
  for (const Asn1Value &element : elements) {
    if (sk_ASN1_TYPE_push(sequence.get(),
                          Asn1TypeCopy(element.value_.get()).release()) == 0) {
      return Status(absl::StatusCode::kInternal, BsslLastErrorString());
    }
  }
  return SetBsslSequence(*sequence);
}

Status Asn1Value::SetIA5String(absl::string_view value) {
  bssl::UniquePtr<ASN1_IA5STRING> ia5_string(ASN1_IA5STRING_new());
  if (ia5_string == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  if (ASN1_STRING_set(ia5_string.get(), value.data(), value.length()) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  ASN1_TYPE_set(value_.get(), V_ASN1_IA5STRING, ia5_string.release());

  return absl::OkStatus();
}

Status Asn1Value::SetSequenceFromStatusOrs(
    absl::Span<const StatusOr<Asn1Value>> results) {
  std::vector<Asn1Value> elements(results.size());
  for (int i = 0; i < results.size(); ++i) {
    ASYLO_ASSIGN_OR_RETURN(elements[i], results[i]);
  }
  return SetSequence(elements);
}

StatusOr<std::vector<uint8_t>> Asn1Value::SerializeToDer() const {
  if (value_ == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument, "Asn1Value is empty");
  }

  unsigned char *der_unowned = nullptr;
  int der_length = i2d_ASN1_TYPE(value_.get(), &der_unowned);
  if (der_length < 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  bssl::UniquePtr<unsigned char> der(der_unowned);
  std::vector<uint8_t> result(der.get(), &der.get()[der_length]);
  return result;
}

StatusOr<Asn1Value> Asn1Value::CreateBooleanFromBssl(ASN1_BOOLEAN bssl_value) {
  Asn1Value asn1;
  ASYLO_RETURN_IF_ERROR(asn1.SetBsslBoolean(bssl_value));
  return asn1;
}

StatusOr<Asn1Value> Asn1Value::CreateIntegerFromBssl(
    const ASN1_INTEGER &bssl_value) {
  Asn1Value asn1;
  ASYLO_RETURN_IF_ERROR(asn1.SetBsslInteger(bssl_value));
  return asn1;
}

StatusOr<Asn1Value> Asn1Value::CreateEnumeratedFromBssl(
    const ASN1_ENUMERATED &bssl_value) {
  Asn1Value asn1;
  ASYLO_RETURN_IF_ERROR(asn1.SetBsslEnumerated(bssl_value));
  return asn1;
}

StatusOr<Asn1Value> Asn1Value::CreateBitStringFromBssl(
    const ASN1_BIT_STRING &bssl_value) {
  Asn1Value asn1;
  ASYLO_RETURN_IF_ERROR(asn1.SetBsslBitString(bssl_value));
  return asn1;
}

StatusOr<Asn1Value> Asn1Value::CreateOctetStringFromBssl(
    const ASN1_OCTET_STRING &bssl_value) {
  Asn1Value asn1;
  ASYLO_RETURN_IF_ERROR(asn1.SetBsslOctetString(bssl_value));
  return asn1;
}

StatusOr<Asn1Value> Asn1Value::CreateObjectIdFromBssl(
    const ASN1_OBJECT &bssl_value) {
  Asn1Value asn1;
  ASYLO_RETURN_IF_ERROR(asn1.SetBsslObjectId(bssl_value));
  return asn1;
}

StatusOr<Asn1Value> Asn1Value::CreateSequenceFromBssl(
    const ASN1_SEQUENCE_ANY &bssl_value) {
  Asn1Value asn1;
  ASYLO_RETURN_IF_ERROR(asn1.SetBsslSequence(bssl_value));
  return asn1;
}

StatusOr<Asn1Value> Asn1Value::CreateIA5StringFromBssl(
    const ASN1_IA5STRING &bssl_value) {
  Asn1Value asn1;
  ASYLO_RETURN_IF_ERROR(asn1.SetBsslIA5String(bssl_value));
  return asn1;
}

StatusOr<ASN1_BOOLEAN> Asn1Value::GetBsslBoolean() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kBoolean));
  return value_->value.boolean;
}

StatusOr<bssl::UniquePtr<ASN1_INTEGER>> Asn1Value::GetBsslInteger() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kInteger));
  return bssl::UniquePtr<ASN1_INTEGER>(
      CHECK_NOTNULL(ASN1_INTEGER_dup(value_->value.integer)));
}

StatusOr<bssl::UniquePtr<ASN1_ENUMERATED>> Asn1Value::GetBsslEnumerated()
    const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kEnumerated));
  return bssl::UniquePtr<ASN1_ENUMERATED>(
      CHECK_NOTNULL(ASN1_STRING_dup(value_->value.enumerated)));
}

StatusOr<bssl::UniquePtr<ASN1_BIT_STRING>> Asn1Value::GetBsslBitString() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kBitString));
  return bssl::UniquePtr<ASN1_BIT_STRING>(
      CHECK_NOTNULL(ASN1_STRING_dup(value_->value.bit_string)));
}

StatusOr<bssl::UniquePtr<ASN1_OCTET_STRING>> Asn1Value::GetBsslOctetString()
    const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kOctetString));
  return bssl::UniquePtr<ASN1_OCTET_STRING>(
      CHECK_NOTNULL(ASN1_OCTET_STRING_dup(value_->value.octet_string)));
}

StatusOr<bssl::UniquePtr<ASN1_OBJECT>> Asn1Value::GetBsslObjectId() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kObjectId));
  return Asn1ObjectCopy(value_->value.object);
}

StatusOr<bssl::UniquePtr<ASN1_SEQUENCE_ANY>> Asn1Value::GetBsslSequence()
    const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kSequence));
  const ASN1_STRING *der_string = value_->value.sequence;
  const unsigned char *der_data = ASN1_STRING_get0_data(der_string);
  bssl::UniquePtr<ASN1_SEQUENCE_ANY> sequence(d2i_ASN1_SEQUENCE_ANY(
      /*a=*/nullptr, &der_data, ASN1_STRING_length(der_string)));
  if (sequence == nullptr) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  // GCC 4.9 requires this std::move() invocation.
  return std::move(sequence);
}

StatusOr<bssl::UniquePtr<ASN1_IA5STRING>> Asn1Value::GetBsslIA5String() const {
  ASYLO_RETURN_IF_ERROR(CheckIsType(Asn1Type::kIA5String));
  return bssl::UniquePtr<ASN1_IA5STRING>(
      CHECK_NOTNULL(ASN1_STRING_dup(value_->value.ia5string)));
}

Status Asn1Value::SetBsslBoolean(ASN1_BOOLEAN bssl_value) {
  // A non-null pointer. Used when calling ASN1_TYPE_set() with V_ASN1_BOOLEAN.
  void *const kNonNullPointer = reinterpret_cast<void *>(true);

  ASN1_TYPE_set(value_.get(), V_ASN1_BOOLEAN,
                bssl_value ? kNonNullPointer : nullptr);
  return absl::OkStatus();
}

Status Asn1Value::SetBsslInteger(const ASN1_INTEGER &bssl_value) {
  if (ASN1_TYPE_set1(value_.get(), V_ASN1_INTEGER, &bssl_value) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

Status Asn1Value::SetBsslEnumerated(const ASN1_ENUMERATED &bssl_value) {
  if (ASN1_TYPE_set1(value_.get(), V_ASN1_ENUMERATED, &bssl_value) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

Status Asn1Value::SetBsslBitString(const ASN1_BIT_STRING &bssl_value) {
  if (ASN1_TYPE_set1(value_.get(), V_ASN1_BIT_STRING, &bssl_value) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

Status Asn1Value::SetBsslOctetString(const ASN1_OCTET_STRING &bssl_value) {
  if (ASN1_TYPE_set1(value_.get(), V_ASN1_OCTET_STRING, &bssl_value) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

Status Asn1Value::SetBsslObjectId(const ASN1_OBJECT &bssl_value) {
  if (ASN1_TYPE_set1(value_.get(), V_ASN1_OBJECT, &bssl_value) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

Status Asn1Value::SetBsslSequence(const ASN1_SEQUENCE_ANY &bssl_value) {
  unsigned char *der_unowned = nullptr;
  int der_length = i2d_ASN1_SEQUENCE_ANY(&bssl_value, &der_unowned);
  if (der_length < 0) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  bssl::UniquePtr<unsigned char> der(der_unowned);

  bssl::UniquePtr<ASN1_STRING> der_string(
      ASN1_STRING_type_new(V_ASN1_SEQUENCE));
  if (ASN1_STRING_set(der_string.get(), der.get(), der_length) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }

  ASN1_TYPE_set(value_.get(), V_ASN1_SEQUENCE, der_string.release());
  return absl::OkStatus();
}

Status Asn1Value::SetBsslIA5String(const ASN1_IA5STRING &bssl_value) {
  if (ASN1_TYPE_set1(value_.get(), V_ASN1_IA5STRING, &bssl_value) != 1) {
    return Status(absl::StatusCode::kInternal, BsslLastErrorString());
  }
  return absl::OkStatus();
}

Asn1Value::Asn1Value(bssl::UniquePtr<ASN1_TYPE> value)
    : value_(std::move(value)) {}

Status Asn1Value::CheckIsType(Asn1Type type) const {
  if (value_ == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument, "Asn1Value is empty");
  }

  int openssl_type = ToOpensslType(type);
  if (value_->type != openssl_type) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrFormat("Asn1Value is a %s, not a %s",
                                  OpensslTypeName(value_->type),
                                  OpensslTypeName(openssl_type)));
  }

  return absl::OkStatus();
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
      return BN_cmp(lhs.GetInteger().value().get(),
                    rhs.GetInteger().value().get()) == 0;
    case Asn1Type::kEnumerated:
      return BN_cmp(lhs.GetEnumerated().value().get(),
                    rhs.GetEnumerated().value().get()) == 0;
    case Asn1Type::kSequence:
      return lhs.GetSequence().value() == rhs.GetSequence().value();
    case Asn1Type::kBoolean:
    case Asn1Type::kBitString:
    case Asn1Type::kObjectId:
    case Asn1Type::kOctetString:
    case Asn1Type::kIA5String:
      return ASN1_TYPE_cmp(lhs.value_.get(), rhs.value_.get()) == 0;
  }

  return false;
}

bool operator!=(const Asn1Value &lhs, const Asn1Value &rhs) {
  return !(lhs == rhs);
}

}  // namespace asylo
