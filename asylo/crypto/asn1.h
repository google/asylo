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

#ifndef ASYLO_CRYPTO_ASN1_H_
#define ASYLO_CRYPTO_ASN1_H_

#include <openssl/asn1.h>
#include <openssl/base.h>

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/bignum_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

// An ASN.1 value type. This enum only lists types supported by Asn1Value. Each
// type is associated with a C++ representation.
enum class Asn1Type {
  // BOOLEAN values are represented by C++ bools.
  kBoolean,

  // INTEGER values are represented by OpenSSL BIGNUMs.
  kInteger,

  // ENUMERATED values are represented by OpenSSL BIGNUMs.
  kEnumerated,

  // BIT STRING values are represented by std::vector<bool>s. Two BIT STRINGs
  // that differ only in the number of trailing zeros are considered equal.
  kBitString,

  // OCTET STRING values are represented by arrays of uint8_ts.
  kOctetString,

  // OBJECT IDENTIFIER values are represented by instances of the ObjectId class
  // defined below.
  kObjectId,

  // SEQUENCE values are represented by arrays of Asn1Values.
  kSequence,

  // IA5String values are represented by an ASCII string.
  kIA5String,
};

// Represents an ASN.1 OBJECT IDENTIFIER. Each object identifier can be
// represented in its "dot" form string (e.g. "1.2.3.4"). OpenSSL also defines
// "short" names, "long" names, and numerical identifiers (NIDs) for many common
// OIDs.
//
// The short names, long names, and NIDs can be found in <openssl/nid.h>.
class ObjectId {
 public:
  ObjectId() = default;

  ObjectId(const ObjectId &other);
  ObjectId &operator=(const ObjectId &other);
  ObjectId(ObjectId &&other) = default;
  ObjectId &operator=(ObjectId &&other) = default;

  // Returns an ObjectId from a short name, a long name, a numerical ID, an OID
  // string like "1.2.3.4", or an ASN1_OBJECT.
  static StatusOr<ObjectId> CreateFromShortName(const std::string &short_name);
  static StatusOr<ObjectId> CreateFromLongName(const std::string &long_name);
  static StatusOr<ObjectId> CreateFromNumericId(int nid);
  static StatusOr<ObjectId> CreateFromOidString(const std::string &oid_string);
  static StatusOr<ObjectId> CreateFromBsslObject(const ASN1_OBJECT &bssl);

  // Returns the short name, long name, numerical ID, or OID string for this
  // OBJECT IDENTIFIER.
  StatusOr<std::string> GetShortName() const;
  StatusOr<std::string> GetLongName() const;
  StatusOr<int> GetNumericId() const;
  StatusOr<std::string> GetOidString() const;

  // Returns a reference to or a copy of the underlying ASN1_OBJECT.
  const ASN1_OBJECT &GetBsslObject() const;
  StatusOr<bssl::UniquePtr<ASN1_OBJECT>> GetBsslObjectCopy() const;

 private:
  friend bool operator==(const ObjectId &lhs, const ObjectId &rhs);

  explicit ObjectId(bssl::UniquePtr<ASN1_OBJECT> object);

  bssl::UniquePtr<ASN1_OBJECT> object_;
};

// Equality/inequality operators for ObjectId.
bool operator==(const ObjectId &lhs, const ObjectId &rhs);
bool operator!=(const ObjectId &lhs, const ObjectId &rhs);

std::ostream &operator<<(std::ostream &out, const ObjectId &oid);

// AbslHashValue() overload for ObjectId.
template <typename H>
H AbslHashValue(H hash, const ObjectId &oid) {
  // BoringSSL ensures that the OID string representation of an object is a
  // sequence of integers with no leading zeroes joined by '.' characters (i.e.
  // matches /((0|[1-9][0-9]*)\.)*(0|[1-9][0-9]*)/). The exact requirements are
  // more strict, but the properties described above guarantee that the hash of
  // the OID string is a valid hash for an ObjectId.
  return H::combine(std::move(hash), oid.GetOidString().value());
}

// Represents a general ASN.1 value. Only some ASN.1 types are supported; see
// the Asn1Type enum for a list of supported types.
//
// An Asn1Value object may represent a value of an unsupported type. In that
// case, calls to Type() will return absl::nullopt and calls to any Get() method
// will return an error.
class Asn1Value {
 public:
  // No guarantees are made about the type and value of a default-constructed
  // Asn1Value.
  Asn1Value();

  // Asn1Value supports both copy and move operations. No guarantees are made
  // about the type and value of a moved-from Asn1Value.
  Asn1Value(const Asn1Value &other);
  Asn1Value &operator=(const Asn1Value &other);
  Asn1Value(Asn1Value &&other);
  Asn1Value &operator=(Asn1Value &&other);

  // Each factory method creates an Asn1Value of the appropriate ASN.1 type from
  // the input data.
  static StatusOr<Asn1Value> CreateBoolean(bool value);
  static StatusOr<Asn1Value> CreateInteger(const BIGNUM &value);
  static StatusOr<Asn1Value> CreateEnumerated(const BIGNUM &value);
  static StatusOr<Asn1Value> CreateBitString(const std::vector<bool> &value);
  static StatusOr<Asn1Value> CreateOctetString(ByteContainerView value);
  static StatusOr<Asn1Value> CreateObjectId(const ObjectId &value);
  static StatusOr<Asn1Value> CreateSequence(
      absl::Span<const Asn1Value> elements);
  static StatusOr<Asn1Value> CreateIA5String(absl::string_view value);

  // Factory methods for creating INTEGER and ENUMERATED values directly from
  // integral types.
  template <typename IntT>
  static StatusOr<Asn1Value> CreateIntegerFromInt(IntT value) {
    Asn1Value result;
    ASYLO_RETURN_IF_ERROR(result.SetIntegerFromInt(value));
    return result;
  }
  template <typename IntT>
  static StatusOr<Asn1Value> CreateEnumeratedFromInt(IntT value) {
    Asn1Value result;
    ASYLO_RETURN_IF_ERROR(result.SetEnumeratedFromInt(value));
    return result;
  }

  // Creates an Asn1Value representing a sequence composed of the values in
  // |values| if all the values are OK. Otherwise, returns an error.
  static StatusOr<Asn1Value> CreateSequenceFromStatusOrs(
      absl::Span<const StatusOr<Asn1Value>> results);

  // Creates an Asn1Value from the DER-encoded |asn1_der|. CreateFromDer() does
  // not fail if |asn1_der| represents an ASN.1 value containing unsupported
  // types.
  static StatusOr<Asn1Value> CreateFromDer(ByteContainerView asn1_der);

  // Returns the type of this value, or absl::nullopt if the contained value has
  // an unsupported type.
  absl::optional<Asn1Type> Type() const;

  // Each getter returns the contained value in the appropriate C++ type. Fails
  // if the Asn1Value does not have the appropriate type.
  //
  // All returned data is copied.
  //
  // The implementation of GetBitString() ensures that either the returned
  // std::vector<bool> is empty or its last element is true, which allows users
  // to use operator==() to correctly compare two return values from
  // GetBitString().
  StatusOr<bool> GetBoolean() const;
  StatusOr<bssl::UniquePtr<BIGNUM>> GetInteger() const;
  StatusOr<bssl::UniquePtr<BIGNUM>> GetEnumerated() const;
  StatusOr<std::vector<bool>> GetBitString() const;
  StatusOr<std::vector<uint8_t>> GetOctetString() const;
  StatusOr<ObjectId> GetObjectId() const;
  StatusOr<std::vector<Asn1Value>> GetSequence() const;
  StatusOr<std::string> GetIA5String() const;

  // Getters that get an INTEGER or ENUMERATED value directly as an integral
  // type.
  template <typename IntT>
  StatusOr<IntT> GetIntegerAsInt() const {
    bssl::UniquePtr<BIGNUM> bignum;
    ASYLO_ASSIGN_OR_RETURN(bignum, GetInteger());
    return IntegerFromBignum<IntT>(*bignum);
  }
  template <typename IntT>
  StatusOr<IntT> GetEnumeratedAsInt() const {
    bssl::UniquePtr<BIGNUM> bignum;
    ASYLO_ASSIGN_OR_RETURN(bignum, GetEnumerated());
    return IntegerFromBignum<IntT>(*bignum);
  }

  // Each setter sets the Asn1Value to have the appropriate type and the given
  // value. If a setter fails, then the value of the Asn1Value is unchanged.
  Status SetBoolean(bool value);
  Status SetInteger(const BIGNUM &value);
  Status SetEnumerated(const BIGNUM &value);
  Status SetBitString(const std::vector<bool> &value);
  Status SetOctetString(ByteContainerView value);
  Status SetObjectId(const ObjectId &value);
  Status SetSequence(absl::Span<const Asn1Value> elements);
  Status SetIA5String(absl::string_view value);

  // Setters for setting an Asn1Value to be an INTEGER or ENUMERATED value from
  // an integral type.
  template <typename IntT>
  Status SetIntegerFromInt(IntT value) {
    bssl::UniquePtr<BIGNUM> bignum;
    ASYLO_ASSIGN_OR_RETURN(bignum, BignumFromInteger(value));
    return SetInteger(*bignum);
  }
  template <typename IntT>
  Status SetEnumeratedFromInt(IntT value) {
    bssl::UniquePtr<BIGNUM> bignum;
    ASYLO_ASSIGN_OR_RETURN(bignum, BignumFromInteger(value));
    return SetEnumerated(*bignum);
  }

  // Sets the Asn1Value to a sequence composed of the values in |values| if all
  // the values are OK. Otherwise, returns an error.
  Status SetSequenceFromStatusOrs(
      absl::Span<const StatusOr<Asn1Value>> results);

  // Serializes this Asn1Value to a DER-encoded string. This function works even
  // on Asn1Values of unsupported types.
  StatusOr<std::vector<uint8_t>> SerializeToDer() const;

  // Each "Bssl" factory method creates an Asn1Value of the appropriate ASN.1
  // type from the input BoringSSL type.
  static StatusOr<Asn1Value> CreateBooleanFromBssl(ASN1_BOOLEAN bssl_value);
  static StatusOr<Asn1Value> CreateIntegerFromBssl(
      const ASN1_INTEGER &bssl_value);
  static StatusOr<Asn1Value> CreateEnumeratedFromBssl(
      const ASN1_ENUMERATED &bssl_value);
  static StatusOr<Asn1Value> CreateBitStringFromBssl(
      const ASN1_BIT_STRING &bssl_value);
  static StatusOr<Asn1Value> CreateOctetStringFromBssl(
      const ASN1_OCTET_STRING &bssl_value);
  static StatusOr<Asn1Value> CreateObjectIdFromBssl(
      const ASN1_OBJECT &bssl_value);
  static StatusOr<Asn1Value> CreateSequenceFromBssl(
      const ASN1_SEQUENCE_ANY &bssl_value);
  static StatusOr<Asn1Value> CreateIA5StringFromBssl(
      const ASN1_IA5STRING &bssl_value);

  // Each "Bssl" getter returns the contained value in the appropriate BoringSSL
  // type. Fails if the Asn1Value does not have the appropriate type.
  //
  // All returned data is copied.
  StatusOr<ASN1_BOOLEAN> GetBsslBoolean() const;
  StatusOr<bssl::UniquePtr<ASN1_INTEGER>> GetBsslInteger() const;
  StatusOr<bssl::UniquePtr<ASN1_ENUMERATED>> GetBsslEnumerated() const;
  StatusOr<bssl::UniquePtr<ASN1_BIT_STRING>> GetBsslBitString() const;
  StatusOr<bssl::UniquePtr<ASN1_OCTET_STRING>> GetBsslOctetString() const;
  StatusOr<bssl::UniquePtr<ASN1_OBJECT>> GetBsslObjectId() const;
  StatusOr<bssl::UniquePtr<ASN1_SEQUENCE_ANY>> GetBsslSequence() const;
  StatusOr<bssl::UniquePtr<ASN1_IA5STRING>> GetBsslIA5String() const;

  // Each "Bssl" setter sets the Asn1Value to have the appropriate type and the
  // given value. If a setter fails, then the value of the Asn1Value is
  // unchanged.
  Status SetBsslBoolean(ASN1_BOOLEAN bssl_value);
  Status SetBsslInteger(const ASN1_INTEGER &bssl_value);
  Status SetBsslEnumerated(const ASN1_ENUMERATED &bssl_value);
  Status SetBsslBitString(const ASN1_BIT_STRING &bssl_value);
  Status SetBsslOctetString(const ASN1_OCTET_STRING &bssl_value);
  Status SetBsslObjectId(const ASN1_OBJECT &bssl_value);
  Status SetBsslSequence(const ASN1_SEQUENCE_ANY &bssl_value);
  Status SetBsslIA5String(const ASN1_IA5STRING &bssl_value);

 private:
  friend bool operator==(const Asn1Value &lhs, const Asn1Value &rhs);

  // Constructs an Asn1Value representing |value|.
  explicit Asn1Value(bssl::UniquePtr<ASN1_TYPE> value);

  // Returns an OK status if this Asn1Value's type is the same as |type|.
  // Otherwise, returns an INVALID_ARGUMENT status describing the mismatch.
  Status CheckIsType(Asn1Type type) const;

  bssl::UniquePtr<ASN1_TYPE> value_;
};

// Equality/inequality operators for Asn1Value. An Asn1Value representing an
// unsupported type is never equal to any other Asn1Value.
bool operator==(const Asn1Value &lhs, const Asn1Value &rhs);
bool operator!=(const Asn1Value &lhs, const Asn1Value &rhs);

}  // namespace asylo

#endif  // ASYLO_CRYPTO_ASN1_H_
