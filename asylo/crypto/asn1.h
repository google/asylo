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
#include <vector>

#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/status.h"
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

  // OCTET STRING values are represented by arrays of uint8_ts.
  kOctetString,

  // OBJECT IDENTIFIER values are represented by OID strings like "1.2.3.4".
  kObjectId,

  // SEQUENCE values are represented by arrays of Asn1Values.
  kSequence,
};

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
  static StatusOr<Asn1Value> CreateIntegerFromInt64(int64_t value);
  static StatusOr<Asn1Value> CreateEnumerated(const BIGNUM &value);
  static StatusOr<Asn1Value> CreateEnumeratedFromInt64(int64_t value);
  static StatusOr<Asn1Value> CreateOctetString(ByteContainerView value);
  static StatusOr<Asn1Value> CreateObjectId(const std::string &oid_string);
  static StatusOr<Asn1Value> CreateSequence(
      absl::Span<const Asn1Value> elements);

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
  StatusOr<bool> GetBoolean() const;
  StatusOr<bssl::UniquePtr<BIGNUM>> GetInteger() const;
  StatusOr<int64_t> GetIntegerAsInt64() const;
  StatusOr<bssl::UniquePtr<BIGNUM>> GetEnumerated() const;
  StatusOr<int64_t> GetEnumeratedAsInt64() const;
  StatusOr<std::vector<uint8_t>> GetOctetString() const;
  StatusOr<std::string> GetObjectId() const;
  StatusOr<std::vector<Asn1Value>> GetSequence() const;

  // Each setter sets the Asn1Value to have the appropriate type and the given
  // value. If a setter fails, then the value of the Asn1Value is unchanged.
  Status SetBoolean(bool value);
  Status SetInteger(const BIGNUM &value);
  Status SetIntegerFromInt64(int64_t value);
  Status SetEnumerated(const BIGNUM &value);
  Status SetEnumeratedFromInt64(int64_t value);
  Status SetOctetString(ByteContainerView value);
  Status SetObjectId(const std::string &oid_string);
  Status SetSequence(absl::Span<const Asn1Value> elements);

  // Serializes this Asn1Value to a DER-encoded string. This function works even
  // on Asn1Values of unsupported types.
  StatusOr<std::vector<uint8_t>> SerializeToDer() const;

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
