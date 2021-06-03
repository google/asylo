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
#include <openssl/nid.h>

#include <cstdint>
#include <iterator>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/hash/hash_testing.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/bignum_util.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/test/util/integral_type_test_data.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

using ::testing::ContainerEq;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Ne;
using ::testing::Not;
using ::testing::Optional;
using ::testing::SizeIs;
using ::testing::Test;
using ::testing::Types;

// A hex string of the DER encoding of a PrintableString value.
constexpr char kUnsupportedValueDerHex[] = "130f5072696e7461626c65537472696e67";

// Prints a BIGNUM value.
std::string PrintBignum(const BIGNUM &bignum) {
  std::pair<Sign, std::vector<uint8_t>> sign_and_bytes =
      BigEndianBytesFromBignum(bignum).value();
  return absl::StrCat(
      sign_and_bytes.first == Sign::kNegative ? "-" : "", "0x",
      absl::BytesToHexString(absl::string_view(
          reinterpret_cast<const char *>(sign_and_bytes.second.data()),
          sign_and_bytes.second.size())));
}

// A type to represent an Asn1Type in a Types<> invocation.
template <Asn1Type kType>
using Asn1TypeTag = std::integral_constant<Asn1Type, kType>;

// A type tag for tests of Asn1Value's functions for converting between INTEGER
// values and IntT.
template <typename IntT>
struct Asn1IntegerConversionTag {};

// A type tag for tests of Asn1Value's functions for converting between
// ENUMERATED values and IntT.
template <typename IntT>
struct Asn1EnumeratedConversionTag {};

// Contains a short name, long name, NID, and OID string for a given OID. All
// pointers should point to data with static storage duration or be nullptr.
struct ShortLongNidOid {
  const char *short_name;
  const char *long_name;
  int nid;
  const char *oid_string;

  constexpr ShortLongNidOid(const char *sn, const char *ln, int nid_num,
                            const char *oid)
      : short_name(sn), long_name(ln), nid(nid_num), oid_string(oid) {}
};

// Short names, long names, NIDs, and OID strings for some common OIDs.
constexpr ShortLongNidOid kShortLongNidOids[] = {
    {SN_md5, LN_md5, NID_md5, "1.2.840.113549.2.5"},
    {SN_commonName, LN_commonName, NID_commonName, "2.5.4.3"},
    {SN_crl_number, LN_crl_number, NID_crl_number, "2.5.29.20"}};

// EXPECTs that |oid| has all the IDs in |ids|.
void ExpectHasIds(const ObjectId &oid, const ShortLongNidOid &ids) {
  EXPECT_THAT(oid.GetShortName(), IsOkAndHolds(ids.short_name));
  EXPECT_THAT(oid.GetLongName(), IsOkAndHolds(ids.long_name));
  EXPECT_THAT(oid.GetNumericId(), IsOkAndHolds(ids.nid));
  EXPECT_THAT(oid.GetOidString(), IsOkAndHolds(ids.oid_string));
}

TEST(Asn1Test, ObjectIdCreateFromShortNameReturnsCorrectObject) {
  for (const auto &ids : kShortLongNidOids) {
    ObjectId oid;
    ASYLO_ASSERT_OK_AND_ASSIGN(oid,
                               ObjectId::CreateFromShortName(ids.short_name));
    ExpectHasIds(oid, ids);
  }
}

TEST(Asn1Test, ObjectIdCreateFromShortNameFailsIfNoSuchName) {
  constexpr const char *kBadShortNames[] = {"xkcd", "Jean-Luc Picard"};

  for (const char *bad_name : kBadShortNames) {
    EXPECT_THAT(ObjectId::CreateFromShortName(bad_name),
                StatusIs(absl::StatusCode::kNotFound));
  }
}

TEST(Asn1Test, ObjectIdCreateFromLongNameReturnsCorrectObject) {
  for (const auto &ids : kShortLongNidOids) {
    ObjectId oid;
    ASYLO_ASSERT_OK_AND_ASSIGN(oid,
                               ObjectId::CreateFromLongName(ids.long_name));
    ExpectHasIds(oid, ids);
  }
}

TEST(Asn1Test, ObjectIdCreateFromLongNameFailsIfNoSuchName) {
  constexpr const char *kBadLongNames[] = {"Oliver Cromwell", "Oscar Wilde"};

  for (const char *bad_name : kBadLongNames) {
    EXPECT_THAT(ObjectId::CreateFromLongName(bad_name),
                StatusIs(absl::StatusCode::kNotFound));
  }
}

TEST(Asn1Test, ObjectIdCreateFromNidReturnsCorrectObject) {
  for (const auto &ids : kShortLongNidOids) {
    ObjectId oid;
    ASYLO_ASSERT_OK_AND_ASSIGN(oid, ObjectId::CreateFromNumericId(ids.nid));
    ExpectHasIds(oid, ids);
  }
}

TEST(Asn1Test, ObjectIdCreateFromNidFailsIfNoSuchNid) {
  constexpr int kBadNids[] = {-1, 8675309};

  for (int bad_nid : kBadNids) {
    EXPECT_THAT(ObjectId::CreateFromNumericId(bad_nid),
                StatusIs(absl::StatusCode::kNotFound));
  }
}

TEST(Asn1Test, ObjectIdCreateFromOidStringReturnsCorrectObject) {
  for (const auto &ids : kShortLongNidOids) {
    ObjectId oid;
    ASYLO_ASSERT_OK_AND_ASSIGN(oid,
                               ObjectId::CreateFromOidString(ids.oid_string));
    ExpectHasIds(oid, ids);
  }
}

TEST(Asn1Test, ObjectIdCreateFromOidStringFailsIfInvalidOid) {
  constexpr const char *kBadOids[] = {"1.2.cranberry", "9..9"};

  for (const char *bad_oid : kBadOids) {
    EXPECT_THAT(ObjectId::CreateFromOidString(bad_oid),
                StatusIs(absl::StatusCode::kInternal));
  }
}

TEST(Asn1Test, ObjectIdGettersFailIfIdNotInBoringssl) {
  constexpr const char *kNoNameOids[] = {"1.2.840.113741.1.13.1",
                                         "1.3.6.1.4.1.11129"};

  for (const char *oid_string : kNoNameOids) {
    ObjectId oid;
    ASYLO_ASSERT_OK_AND_ASSIGN(oid, ObjectId::CreateFromOidString(oid_string));
    EXPECT_THAT(oid.GetShortName(), StatusIs(absl::StatusCode::kNotFound));
    EXPECT_THAT(oid.GetLongName(), StatusIs(absl::StatusCode::kNotFound));
    EXPECT_THAT(oid.GetNumericId(), StatusIs(absl::StatusCode::kNotFound));
    EXPECT_THAT(oid.GetOidString(), IsOkAndHolds(oid_string));
  }
}

TEST(Asn1Test, ObjectIdBsslRoundtripDoesNotChangeValue) {
  for (const auto &ids : kShortLongNidOids) {
    ObjectId original;
    ASYLO_ASSERT_OK_AND_ASSIGN(original,
                               ObjectId::CreateFromOidString(ids.oid_string));
    ObjectId roundtrip;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        roundtrip, ObjectId::CreateFromBsslObject(original.GetBsslObject()));
    ExpectHasIds(roundtrip, ids);
  }
}

TEST(Asn1Test, ObjectIdBsslCopyRoundtripDoesNotChangeValue) {
  for (const auto &ids : kShortLongNidOids) {
    ObjectId original;
    ASYLO_ASSERT_OK_AND_ASSIGN(original,
                               ObjectId::CreateFromOidString(ids.oid_string));
    bssl::UniquePtr<ASN1_OBJECT> bssl;
    ASYLO_ASSERT_OK_AND_ASSIGN(bssl, original.GetBsslObjectCopy());
    ObjectId roundtrip;
    ASYLO_ASSERT_OK_AND_ASSIGN(roundtrip,
                               ObjectId::CreateFromBsslObject(*bssl));
    ExpectHasIds(roundtrip, ids);
  }
}

TEST(Asn1Test, ObjectIdEquality) {
  for (int i = 0; i < ABSL_ARRAYSIZE(kShortLongNidOids); ++i) {
    ObjectId lhs;
    ASYLO_ASSERT_OK_AND_ASSIGN(
        lhs, ObjectId::CreateFromOidString(kShortLongNidOids[i].oid_string));
    for (int j = 0; j < ABSL_ARRAYSIZE(kShortLongNidOids); ++j) {
      ObjectId rhs;
      ASYLO_ASSERT_OK_AND_ASSIGN(
          rhs, ObjectId::CreateFromOidString(kShortLongNidOids[j].oid_string));

      // Eq() calls operator== and Ne() calls operator!=. We should test that
      // both operators return the correct value in each case.
      if (i == j) {
        EXPECT_THAT(lhs, Eq(rhs));
        EXPECT_THAT(lhs, Not(Ne(rhs)));
      } else {
        EXPECT_THAT(lhs, Not(Eq(rhs)));
        EXPECT_THAT(lhs, Ne(rhs));
      }
    }
  }
}

TEST(Asn1Test, ObjectIdEqualityWithEmptyOid) {
  ObjectId cn;
  ASYLO_ASSERT_OK_AND_ASSIGN(cn, ObjectId::CreateFromShortName("CN"));
  ObjectId empty;

  EXPECT_THAT(cn, Not(Eq(empty)));
  EXPECT_THAT(cn, Ne(empty));

  EXPECT_THAT(empty, Ne(cn));
  EXPECT_THAT(empty, Not(Eq(cn)));

  EXPECT_THAT(empty, Eq(empty));
  EXPECT_THAT(empty, Not(Ne(empty)));
}

TEST(Asn1Test, ObjectIdCopyConstructionPreservesEquality) {
  for (const auto &ids : kShortLongNidOids) {
    ObjectId oid;
    ASYLO_ASSERT_OK_AND_ASSIGN(oid,
                               ObjectId::CreateFromOidString(ids.oid_string));
    ObjectId copy(oid);
    EXPECT_THAT(copy, Eq(oid));
  }
}

TEST(Asn1Test, ObjectIdCopyAssignmentPreservesEquality) {
  for (const auto &ids : kShortLongNidOids) {
    ObjectId oid;
    ASYLO_ASSERT_OK_AND_ASSIGN(oid,
                               ObjectId::CreateFromOidString(ids.oid_string));
    ObjectId copy = oid;
    EXPECT_THAT(copy, Eq(oid));
  }
}

TEST(Asn1Test, AbslHashValueForObjectIdBehavesCorrectly) {
  constexpr const char *kNoNameOids[] = {"1.2.840.113741.1.13.1",
                                         "1.3.6.1.4.1.11129"};

  std::vector<ObjectId> oids;
  for (const auto &ids : kShortLongNidOids) {
    ObjectId oid;
    ASYLO_ASSERT_OK_AND_ASSIGN(oid,
                               ObjectId::CreateFromOidString(ids.oid_string));
    oids.push_back(std::move(oid));
  }
  for (const char *oid_string : kNoNameOids) {
    ObjectId oid;
    ASYLO_ASSERT_OK_AND_ASSIGN(oid, ObjectId::CreateFromOidString(oid_string));
    oids.push_back(std::move(oid));
  }

  EXPECT_TRUE(absl::VerifyTypeImplementsAbslHashCorrectly(oids));
}

TEST(Asn1Test, ObjectIdOutputShortName) {
  ObjectId oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(oid, ObjectId::CreateFromShortName("CN"));

  std::ostringstream out;
  out << oid;
  EXPECT_THAT(out.str(), Eq("CN"));
}

TEST(Asn1Test, ObjectIdOutputOid) {
  ObjectId oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(oid, ObjectId::CreateFromOidString("1.2.3.4"));

  std::ostringstream out;
  out << oid;
  EXPECT_THAT(out.str(), Eq("1.2.3.4"));
}

TEST(Asn1Test, ObjectIdOutputUnknown) {
  std::ostringstream out;
  out << ObjectId{};
  EXPECT_THAT(out.str(), Eq("UNKNOWN_OID"));
}

TEST(Asn1Test, CreateSequenceFromStatusOrsCreatesCorrectValueIfAllInputsAreOk) {
  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateSequenceFromStatusOrs({}));
  EXPECT_THAT(asn1.GetSequence(), IsOkAndHolds(IsEmpty()));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateSequenceFromStatusOrs(
                                       {Asn1Value::CreateBoolean(true)}));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, asn1.GetSequence());
  ASSERT_THAT(elements, SizeIs(1));
  EXPECT_THAT(elements[0].GetBoolean(), IsOkAndHolds(true));

  ASYLO_ASSERT_OK_AND_ASSIGN(
      asn1,
      Asn1Value::CreateSequenceFromStatusOrs(
          {Asn1Value::CreateBoolean(false), Asn1Value::CreateIntegerFromInt(17),
           Asn1Value::CreateOctetString("\x04\x02")}));
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, asn1.GetSequence());
  ASSERT_THAT(elements, SizeIs(3));
  EXPECT_THAT(elements[0].GetBoolean(), IsOkAndHolds(false));
  EXPECT_THAT(elements[1].GetIntegerAsInt<int>(), IsOkAndHolds(17));
  EXPECT_THAT(elements[2].GetOctetString(),
              IsOkAndHolds(std::vector<uint8_t>({4, 2})));
}

TEST(Asn1Test, CreateSequenceFromStatusOrsFailsIfAnyInputsAreNotOk) {
  EXPECT_THAT(Asn1Value::CreateSequenceFromStatusOrs(
                  {Status(absl::StatusCode::kOutOfRange, "foobar")}),
              StatusIs(absl::StatusCode::kOutOfRange, "foobar"));
  EXPECT_THAT(Asn1Value::CreateSequenceFromStatusOrs(
                  {Asn1Value::CreateBoolean(false),
                   Status(absl::StatusCode::kOutOfRange, "foobar")}),
              StatusIs(absl::StatusCode::kOutOfRange, "foobar"));
  EXPECT_THAT(Asn1Value::CreateSequenceFromStatusOrs(
                  {Status(absl::StatusCode::kOutOfRange, "foobar"),
                   Asn1Value::CreateBoolean(false)}),
              StatusIs(absl::StatusCode::kOutOfRange, "foobar"));
}

TEST(Asn1Test, SetSequenceFromStatusOrsCreatesCorrectValueIfAllInputsAreOk) {
  Asn1Value asn1;
  ASYLO_ASSERT_OK(asn1.SetSequenceFromStatusOrs({}));
  EXPECT_THAT(asn1.GetSequence(), IsOkAndHolds(IsEmpty()));

  ASYLO_ASSERT_OK(
      asn1.SetSequenceFromStatusOrs({Asn1Value::CreateBoolean(true)}));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, asn1.GetSequence());
  ASSERT_THAT(elements, SizeIs(1));
  EXPECT_THAT(elements[0].GetBoolean(), IsOkAndHolds(true));

  ASYLO_ASSERT_OK(asn1.SetSequenceFromStatusOrs(
      {Asn1Value::CreateBoolean(false), Asn1Value::CreateIntegerFromInt(17),
       Asn1Value::CreateOctetString("\x04\x02")}));
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, asn1.GetSequence());
  ASSERT_THAT(elements, SizeIs(3));
  EXPECT_THAT(elements[0].GetBoolean(), IsOkAndHolds(false));
  EXPECT_THAT(elements[1].GetIntegerAsInt<int>(), IsOkAndHolds(17));
  EXPECT_THAT(elements[2].GetOctetString(),
              IsOkAndHolds(std::vector<uint8_t>({4, 2})));
}

TEST(Asn1Test, SetSequenceFromStatusOrsFailsIfAnyInputsAreNotOk) {
  Asn1Value asn1;
  EXPECT_THAT(asn1.SetSequenceFromStatusOrs(
                  {Status(absl::StatusCode::kOutOfRange, "foobar")}),
              StatusIs(absl::StatusCode::kOutOfRange, "foobar"));
  EXPECT_THAT(asn1.SetSequenceFromStatusOrs(
                  {Asn1Value::CreateBoolean(false),
                   Status(absl::StatusCode::kOutOfRange, "foobar")}),
              StatusIs(absl::StatusCode::kOutOfRange, "foobar"));
  EXPECT_THAT(asn1.SetSequenceFromStatusOrs(
                  {Status(absl::StatusCode::kOutOfRange, "foobar"),
                   Asn1Value::CreateBoolean(false)}),
              StatusIs(absl::StatusCode::kOutOfRange, "foobar"));
}

// A template fixture for testing with each of the ASN.1 value types that
// Asn1Value supports. T must be an invocation of Asn1TypeTag,
// Asn1IntegerConversionTag, or Asn1EnumeratedConversionTag. Each
// specialization of Asn1Test should look like:
//
//     template <...>
//     class Asn1Test<...> : public Test {
//      public:
//       // The C++ type to use to represent owned mutable values of the ASN.1
//       // type being tested.
//       using ValueType = ...;
//
//       // The OpenSSL object type to use to represent owned mutable values of
//       // the ASN.1 type being tested.
//       using BsslValueType = ...;
//
//       // The Asn1Type being tested.
//       static constexpr Asn1Type Type() {
//         ...
//       }
//
//       // Test data for kSomeType. None of the values should be equal to each
//       // other when converted to Asn1Values via Create().
//       static std::vector<ValueType> TestData() {
//         ...
//       }
//
//       // Test data where every element in each inner std::vector<...> should
//       // be equal when converted to Asn1Values via Create(). However, values
//       // from different inner vectors should not be equal when converted to
//       // Asn1Values via Create().
//       static std::vector<std::vector<ValueType>> EqualTestData() {
//         ...
//       }
//
//       // Test data that should cause the Asn1Value factory function and
//       // setter for kSomeType to fail.
//       static std::vector<ValueType> BadTestData() {
//         ...
//       }
//
//       // Tests whether |lhs| and |rhs| are equal.
//       static void ExpectEqual(const ValueType &lhs,
//                               const ValueType &rhs) {
//         ...
//       }
//
//       // A wrapper for the appropriate Asn1Value factory method.
//       static StatusOr<Asn1Value> Create(const ValueType &value) { ... }
//
//       // A wrapper for the appropriate Asn1Value getter method.
//       static StatusOr<ValueType> Get(const Asn1Value &asn1) { ... }
//
//       // A wrapper for the appropriate Asn1Value setter method.
//       static Status Set(Asn1Value *asn1, const ValueType &value) { ... }
//
//       // A wrapper for the appropriate Asn1Value "Bssl" factory method.
//       static StatusOr<Asn1Value> CreateFromBssl(
//           const BsslValueType &bssl_value) {
//         ...
//       }
//
//       // A wrapper for the appropriate Asn1Value "Bssl" getter method.
//       static StatusOr<BsslValueType> GetBssl(const Asn1Value &asn1) { ... }
//
//       // A wrapper for the appropriate Asn1Value "Bssl" setter method.
//       static Status SetBssl(Asn1Value *asn1,
//                             const BsslValueType &bssl_value) { ... }
//     };
template <typename T>
class Asn1Test;

// Specialization of Asn1Test for Asn1Type::kBoolean.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kBoolean>> : public Test {
 public:
  using ValueType = bool;
  using BsslValueType = ASN1_BOOLEAN;

  static constexpr Asn1Type Type() { return Asn1Type::kBoolean; }

  static std::vector<ValueType> TestData() { return {false, true}; }

  static std::vector<std::vector<ValueType>> EqualTestData() { return {}; }

  static std::vector<ValueType> BadTestData() { return {}; }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    EXPECT_THAT(lhs, Eq(rhs));
  }

  static StatusOr<Asn1Value> Create(const ValueType &value) {
    return Asn1Value::CreateBoolean(value);
  }

  static StatusOr<ValueType> Get(const Asn1Value &asn1) {
    return asn1.GetBoolean();
  }

  static Status Set(Asn1Value *asn1, const ValueType &value) {
    return asn1->SetBoolean(value);
  }

  static StatusOr<Asn1Value> CreateFromBssl(const BsslValueType &bssl_value) {
    return Asn1Value::CreateBooleanFromBssl(bssl_value);
  }

  static StatusOr<BsslValueType> GetBssl(const Asn1Value &asn1) {
    return asn1.GetBsslBoolean();
  }

  static Status SetBssl(Asn1Value *asn1, const BsslValueType &bssl_value) {
    return asn1->SetBsslBoolean(bssl_value);
  }
};

// Specialization of Asn1Test for Asn1Type::kInteger.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kInteger>> : public Test {
 public:
  using ValueType = bssl::UniquePtr<BIGNUM>;
  using BsslValueType = bssl::UniquePtr<ASN1_INTEGER>;

  static constexpr Asn1Type Type() { return Asn1Type::kInteger; }

  static std::vector<ValueType> TestData() {
    bssl::UniquePtr<BIGNUM> test_data[] = {
        std::move(BignumFromInteger(0)).value(),
        std::move(BignumFromInteger(343)).value(),
        std::move(BignumFromInteger(-1729)).value(),
        std::move(BignumFromBigEndianBytes("0123456789abcdef")).value(),
        std::move(BignumFromBigEndianBytes("0123456789abcdef", Sign::kNegative))
            .value()};
    return std::vector<bssl::UniquePtr<BIGNUM>>(
        std::make_move_iterator(std::begin(test_data)),
        std::make_move_iterator(std::end(test_data)));
  }

  static std::vector<std::vector<ValueType>> EqualTestData() { return {}; }

  static std::vector<ValueType> BadTestData() { return {}; }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    EXPECT_THAT(BN_cmp(lhs.get(), rhs.get()), Eq(0))
        << absl::StrFormat("%s != %s", PrintBignum(*lhs), PrintBignum(*rhs));
  }

  static StatusOr<Asn1Value> Create(const ValueType &value) {
    return Asn1Value::CreateInteger(*value);
  }

  static StatusOr<ValueType> Get(const Asn1Value &asn1) {
    return asn1.GetInteger();
  }

  static Status Set(Asn1Value *asn1, const ValueType &value) {
    return asn1->SetInteger(*value);
  }

  static StatusOr<Asn1Value> CreateFromBssl(const BsslValueType &bssl_value) {
    return Asn1Value::CreateIntegerFromBssl(*bssl_value);
  }

  static StatusOr<BsslValueType> GetBssl(const Asn1Value &asn1) {
    return asn1.GetBsslInteger();
  }

  static Status SetBssl(Asn1Value *asn1, const BsslValueType &bssl_value) {
    return asn1->SetBsslInteger(*bssl_value);
  }
};

// Specialization of Asn1Test for converting between INTEGER values and integral
// types. Does not test conversions with BoringSSL types.
template <typename IntT>
class Asn1Test<Asn1IntegerConversionTag<IntT>> : public Test {
 public:
  using ValueType = IntT;
  using BsslValueType = Asn1Value;

  static constexpr Asn1Type Type() { return Asn1Type::kInteger; }

  static std::vector<ValueType> TestData() {
    return std::vector<IntT>(std::begin(IntegralTypeTestData<IntT>::kValues),
                             std::end(IntegralTypeTestData<IntT>::kValues));
  }

  static std::vector<std::vector<ValueType>> EqualTestData() { return {}; }

  static std::vector<ValueType> BadTestData() { return {}; }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    EXPECT_THAT(lhs, Eq(rhs));
  }

  static StatusOr<Asn1Value> Create(const ValueType &value) {
    return Asn1Value::CreateIntegerFromInt(value);
  }

  static StatusOr<ValueType> Get(const Asn1Value &asn1) {
    return asn1.GetIntegerAsInt<IntT>();
  }

  static Status Set(Asn1Value *asn1, const ValueType &value) {
    return asn1->SetIntegerFromInt(value);
  }

  static StatusOr<Asn1Value> CreateFromBssl(const BsslValueType &bssl_value) {
    return bssl_value;
  }

  static StatusOr<BsslValueType> GetBssl(const Asn1Value &asn1) { return asn1; }

  static Status SetBssl(Asn1Value *asn1, const BsslValueType &bssl_value) {
    *asn1 = bssl_value;
    return absl::OkStatus();
  }
};

// Specialization of Asn1Test for Asn1Type::kEnumerated.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kEnumerated>> : public Test {
 public:
  // ENUMERATED tests re-use functionality from INTEGER tests.
  using Base = Asn1Test<Asn1TypeTag<Asn1Type::kInteger>>;

  using ValueType = Base::ValueType;
  using BsslValueType = bssl::UniquePtr<ASN1_ENUMERATED>;

  static constexpr Asn1Type Type() { return Asn1Type::kEnumerated; }

  static std::vector<ValueType> TestData() { return Base::TestData(); }

  static std::vector<std::vector<ValueType>> EqualTestData() { return {}; }

  static std::vector<ValueType> BadTestData() { return Base::BadTestData(); }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    Base::ExpectEqual(lhs, rhs);
  }

  static StatusOr<Asn1Value> Create(const ValueType &value) {
    return Asn1Value::CreateEnumerated(*value);
  }

  static StatusOr<ValueType> Get(const Asn1Value &asn1) {
    return asn1.GetEnumerated();
  }

  static Status Set(Asn1Value *asn1, const ValueType &value) {
    return asn1->SetEnumerated(*value);
  }

  static StatusOr<Asn1Value> CreateFromBssl(const BsslValueType &bssl_value) {
    return Asn1Value::CreateEnumeratedFromBssl(*bssl_value);
  }

  static StatusOr<BsslValueType> GetBssl(const Asn1Value &asn1) {
    return asn1.GetBsslEnumerated();
  }

  static Status SetBssl(Asn1Value *asn1, const BsslValueType &bssl_value) {
    return asn1->SetBsslEnumerated(*bssl_value);
  }
};

// Specialization of Asn1Test for converting between ENUMERATED values and
// integral types. Does not test conversions with BoringSSL types.
template <typename IntT>
class Asn1Test<Asn1EnumeratedConversionTag<IntT>> : public Test {
 public:
  // ENUMERATED tests re-use functionality from INTEGER tests.
  using Base = Asn1Test<Asn1IntegerConversionTag<IntT>>;

  using ValueType = typename Base::ValueType;
  using BsslValueType = typename Base::BsslValueType;

  static constexpr Asn1Type Type() { return Asn1Type::kEnumerated; }

  static std::vector<ValueType> TestData() { return Base::TestData(); }

  static std::vector<std::vector<ValueType>> EqualTestData() { return {}; }

  static std::vector<ValueType> BadTestData() { return Base::BadTestData(); }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    Base::ExpectEqual(lhs, rhs);
  }

  static StatusOr<Asn1Value> Create(const ValueType &value) {
    return Asn1Value::CreateEnumeratedFromInt(value);
  }

  static StatusOr<ValueType> Get(const Asn1Value &asn1) {
    return asn1.GetEnumeratedAsInt<IntT>();
  }

  static Status Set(Asn1Value *asn1, const ValueType &value) {
    return asn1->SetEnumeratedFromInt(value);
  }

  static StatusOr<Asn1Value> CreateFromBssl(const BsslValueType &bssl_value) {
    return Base::CreateFromBssl(bssl_value);
  }

  static StatusOr<BsslValueType> GetBssl(const Asn1Value &asn1) {
    return Base::GetBssl(asn1);
  }

  static Status SetBssl(Asn1Value *asn1, const BsslValueType &bssl_value) {
    return Base::SetBssl(asn1, bssl_value);
  }
};

// Specialization of Asn1Test for Asn1Type::kBitString.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kBitString>> : public Test {
 public:
  using ValueType = std::vector<bool>;
  using BsslValueType = bssl::UniquePtr<ASN1_BIT_STRING>;

  static constexpr Asn1Type Type() { return Asn1Type::kBitString; }

  static std::vector<ValueType> TestData() {
    return {{},
            {true},
            {false, true, true, false, true, false, false, true},
            {false, true, true, false, true, false, false, true, true},
            {false, true, true, false, true, false, false, true, true, false,
             false, true, false, true, true}};
  }

  static std::vector<std::vector<ValueType>> EqualTestData() {
    return {{{}, {false}, {false, false, false}},
            {{true, false, true}, {true, false, true, false, false}},
            {{false, true, true, false, true, false, false, true, true, false,
              false, true, false, true, true, false},
             {false, true, true, false, true, false, false, true, true, false,
              false, true, false, true, true, false, false, false, false}}};
  }

  static std::vector<ValueType> BadTestData() { return {}; }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    EXPECT_THAT(lhs, ContainerEq(rhs));
  }

  static StatusOr<Asn1Value> Create(const ValueType &value) {
    return Asn1Value::CreateBitString(value);
  }

  static StatusOr<ValueType> Get(const Asn1Value &asn1) {
    return asn1.GetBitString();
  }

  static Status Set(Asn1Value *asn1, const ValueType &value) {
    return asn1->SetBitString(value);
  }

  static StatusOr<Asn1Value> CreateFromBssl(const BsslValueType &bssl_value) {
    return Asn1Value::CreateBitStringFromBssl(*bssl_value);
  }

  static StatusOr<BsslValueType> GetBssl(const Asn1Value &asn1) {
    return asn1.GetBsslBitString();
  }

  static Status SetBssl(Asn1Value *asn1, const BsslValueType &bssl_value) {
    return asn1->SetBsslBitString(*bssl_value);
  }
};

// Specialization of Asn1Test for Asn1Type::kOctetString.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kOctetString>> : public Test {
 public:
  using ValueType = std::vector<uint8_t>;
  using BsslValueType = bssl::UniquePtr<ASN1_OCTET_STRING>;

  static constexpr Asn1Type Type() { return Asn1Type::kOctetString; }

  static std::vector<ValueType> TestData() {
    return {{}, {1}, {1, 1, 2, 3, 5, 8, 13, 21, 34, 55}, {4, 0, 4}};
  }

  static std::vector<std::vector<ValueType>> EqualTestData() { return {}; }

  static std::vector<ValueType> BadTestData() { return {}; }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    EXPECT_THAT(lhs, ContainerEq(rhs));
  }

  static StatusOr<Asn1Value> Create(const ValueType &value) {
    return Asn1Value::CreateOctetString(value);
  }

  static StatusOr<ValueType> Get(const Asn1Value &asn1) {
    return asn1.GetOctetString();
  }

  static Status Set(Asn1Value *asn1, const ValueType &value) {
    return asn1->SetOctetString(value);
  }

  static StatusOr<Asn1Value> CreateFromBssl(const BsslValueType &bssl_value) {
    return Asn1Value::CreateOctetStringFromBssl(*bssl_value);
  }

  static StatusOr<BsslValueType> GetBssl(const Asn1Value &asn1) {
    return asn1.GetBsslOctetString();
  }

  static Status SetBssl(Asn1Value *asn1, const BsslValueType &bssl_value) {
    return asn1->SetBsslOctetString(*bssl_value);
  }
};

// Specialization of Asn1Test for Asn1Type::kObjectId.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kObjectId>> : public Test {
 public:
  using ValueType = ObjectId;
  using BsslValueType = bssl::UniquePtr<ASN1_OBJECT>;

  static constexpr Asn1Type Type() { return Asn1Type::kObjectId; }

  static std::vector<ValueType> TestData() {
    return {ObjectId::CreateFromShortName("CN").value(),
            ObjectId::CreateFromOidString("1.2").value(),
            ObjectId::CreateFromOidString("1.2.840").value(),
            ObjectId::CreateFromOidString("1.2.840.113549.1").value(),
            ObjectId::CreateFromOidString("1.3.6.1.4.1.11129").value(),
            ObjectId::CreateFromOidString("2.5").value(),
            ObjectId::CreateFromOidString("2.5.8").value()};
  }

  static std::vector<std::vector<ValueType>> EqualTestData() { return {}; }

  static std::vector<ValueType> BadTestData() { return {}; }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    EXPECT_THAT(lhs, Eq(rhs))
        << absl::StrFormat("\"%s\" != \"%s\"", lhs.GetOidString().value(),
                           rhs.GetOidString().value());
  }

  static StatusOr<Asn1Value> Create(const ValueType &value) {
    return Asn1Value::CreateObjectId(value);
  }

  static StatusOr<ValueType> Get(const Asn1Value &asn1) {
    return asn1.GetObjectId();
  }

  static Status Set(Asn1Value *asn1, const ValueType &value) {
    return asn1->SetObjectId(value);
  }

  static StatusOr<Asn1Value> CreateFromBssl(const BsslValueType &bssl_value) {
    return Asn1Value::CreateObjectIdFromBssl(*bssl_value);
  }

  static StatusOr<BsslValueType> GetBssl(const Asn1Value &asn1) {
    return asn1.GetBsslObjectId();
  }

  static Status SetBssl(Asn1Value *asn1, const BsslValueType &bssl_value) {
    return asn1->SetBsslObjectId(*bssl_value);
  }
};

// Specialization of Asn1Test for Asn1Type::kSequence.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kSequence>> : public Test {
 public:
  using ValueType = std::vector<Asn1Value>;
  using BsslValueType = bssl::UniquePtr<ASN1_SEQUENCE_ANY>;

  static constexpr Asn1Type Type() { return Asn1Type::kSequence; }

  static std::vector<ValueType> TestData() {
    return {
        {},
        {Asn1Value::CreateBoolean(false).value()},
        {Asn1Value::CreateOctetString("foobar").value(),
         Asn1Value::CreateBoolean(true).value(),
         Asn1Value::CreateOctetString("raboof").value()},
        {Asn1Value::CreateSequence({Asn1Value::CreateBoolean(true).value(),
                                    Asn1Value::CreateBoolean(false).value()})
             .value()}};
  }

  static std::vector<std::vector<ValueType>> EqualTestData() { return {}; }

  static std::vector<ValueType> BadTestData() { return {}; }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    EXPECT_THAT(lhs, ContainerEq(rhs));
  }

  static StatusOr<Asn1Value> Create(const ValueType &value) {
    return Asn1Value::CreateSequence(absl::MakeSpan(value));
  }

  static StatusOr<ValueType> Get(const Asn1Value &asn1) {
    return asn1.GetSequence();
  }

  static Status Set(Asn1Value *asn1, const ValueType &value) {
    return asn1->SetSequence(absl::MakeSpan(value));
  }

  static StatusOr<Asn1Value> CreateFromBssl(const BsslValueType &bssl_value) {
    return Asn1Value::CreateSequenceFromBssl(*bssl_value);
  }

  static StatusOr<BsslValueType> GetBssl(const Asn1Value &asn1) {
    return asn1.GetBsslSequence();
  }

  static Status SetBssl(Asn1Value *asn1, const BsslValueType &bssl_value) {
    return asn1->SetBsslSequence(*bssl_value);
  }
};

// Specialization of Asn1Test for Asn1Type::kIA5String.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kIA5String>> : public Test {
 public:
  using ValueType = std::string;
  using BsslValueType = bssl::UniquePtr<ASN1_IA5STRING>;

  static constexpr Asn1Type Type() { return Asn1Type::kIA5String; }

  static std::vector<ValueType> TestData() {
    return {"", "t", "Test string.", "This is a test string.",
            "This has \0 null \0\0 characters"};
  }

  static std::vector<std::vector<ValueType>> EqualTestData() { return {}; }

  static std::vector<ValueType> BadTestData() { return {}; }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    EXPECT_THAT(lhs, Eq(rhs));
  }

  static StatusOr<Asn1Value> Create(const ValueType &value) {
    return Asn1Value::CreateIA5String(value);
  }

  static StatusOr<ValueType> Get(const Asn1Value &asn1) {
    return asn1.GetIA5String();
  }

  static Status Set(Asn1Value *asn1, const ValueType &value) {
    return asn1->SetIA5String(value);
  }

  static StatusOr<Asn1Value> CreateFromBssl(const BsslValueType &bssl_value) {
    return Asn1Value::CreateIA5StringFromBssl(*bssl_value);
  }

  static StatusOr<BsslValueType> GetBssl(const Asn1Value &asn1) {
    return asn1.GetBsslIA5String();
  }

  static Status SetBssl(Asn1Value *asn1, const BsslValueType &bssl_value) {
    return asn1->SetBsslIA5String(*bssl_value);
  }
};

using Asn1TestingTypes = Types<
    Asn1TypeTag<Asn1Type::kBoolean>, Asn1TypeTag<Asn1Type::kInteger>,
    Asn1IntegerConversionTag<int8_t>, Asn1IntegerConversionTag<uint8_t>,
    Asn1IntegerConversionTag<int16_t>, Asn1IntegerConversionTag<uint16_t>,
    Asn1IntegerConversionTag<int32_t>, Asn1IntegerConversionTag<uint32_t>,
    Asn1IntegerConversionTag<int64_t>, Asn1IntegerConversionTag<uint16_t>,
    Asn1TypeTag<Asn1Type::kEnumerated>, Asn1EnumeratedConversionTag<int8_t>,
    Asn1EnumeratedConversionTag<uint8_t>, Asn1EnumeratedConversionTag<int16_t>,
    Asn1EnumeratedConversionTag<uint16_t>, Asn1EnumeratedConversionTag<int32_t>,
    Asn1EnumeratedConversionTag<uint32_t>, Asn1EnumeratedConversionTag<int64_t>,
    Asn1EnumeratedConversionTag<uint16_t>, Asn1TypeTag<Asn1Type::kBitString>,
    Asn1TypeTag<Asn1Type::kOctetString>, Asn1TypeTag<Asn1Type::kObjectId>,
    Asn1TypeTag<Asn1Type::kSequence>, Asn1TypeTag<Asn1Type::kIA5String>>;
TYPED_TEST_SUITE(Asn1Test, Asn1TestingTypes);

// std::vector<Asn1ValueType<TestParam::value>>::const_reference is used for
// iteration in the tests below because std::vector<bool>::const_iterator
// dereferences to a special bit-view class, not to bool or const bool &.

TYPED_TEST(Asn1Test, CreateCreatesAsn1ValueWithCorrectTypeAndValue) {
  Asn1Value asn1;
  for (const auto &value : TestFixture::TestData()) {
    ASYLO_ASSERT_OK_AND_ASSIGN(asn1, TestFixture::Create(value));
    EXPECT_THAT(asn1.Type(), Optional(TestFixture::Type()));

    typename TestFixture::ValueType roundtrip;
    ASYLO_ASSERT_OK_AND_ASSIGN(roundtrip, TestFixture::Get(asn1));
    TestFixture::ExpectEqual(roundtrip, value);
  }
}

TYPED_TEST(Asn1Test, CreateFailsWithBadInputs) {
  for (const auto &value : TestFixture::BadTestData()) {
    EXPECT_THAT(TestFixture::Create(value),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TYPED_TEST(Asn1Test, SetterSetsAsn1ValueToHaveCorrectTypeAndValue) {
  Asn1Value asn1;
  for (const auto &value : TestFixture::TestData()) {
    ASYLO_ASSERT_OK(TestFixture::Set(&asn1, value));
    EXPECT_THAT(asn1.Type(), Optional(TestFixture::Type()));

    typename TestFixture::ValueType roundtrip;
    ASYLO_ASSERT_OK_AND_ASSIGN(roundtrip, TestFixture::Get(asn1));
    TestFixture::ExpectEqual(roundtrip, value);
  }
}

TYPED_TEST(Asn1Test, SetterFailsWithBadInputs) {
  Asn1Value asn1;
  for (const auto &value : TestFixture::BadTestData()) {
    EXPECT_THAT(TestFixture::Set(&asn1, value),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
}

TYPED_TEST(Asn1Test, CopyConstructedAsn1ValuesContainSameValueAsOriginal) {
  Asn1Value asn1;
  for (const auto &value : TestFixture::TestData()) {
    ASYLO_ASSERT_OK_AND_ASSIGN(asn1, TestFixture::Create(value));

    Asn1Value copy_constructed(asn1);
    typename TestFixture::ValueType copied_value;
    ASYLO_ASSERT_OK_AND_ASSIGN(copied_value,
                               TestFixture::Get(copy_constructed));
    TestFixture::ExpectEqual(copied_value, value);
  }
}

TYPED_TEST(Asn1Test, CopyAssignedAsn1ValuesContainSameValueAsOriginal) {
  Asn1Value asn1;
  for (const auto &value : TestFixture::TestData()) {
    ASYLO_ASSERT_OK_AND_ASSIGN(asn1, TestFixture::Create(value));

    Asn1Value copy_assigned = asn1;
    typename TestFixture::ValueType copied_value;
    ASYLO_ASSERT_OK_AND_ASSIGN(copied_value, TestFixture::Get(copy_assigned));
    TestFixture::ExpectEqual(copied_value, value);
  }
}

TYPED_TEST(
    Asn1Test,
    Asn1ValuesOfSameTypeAreEqualIfAndOnlyIfConstructedFromEquivalentData) {
  std::vector<typename TestFixture::ValueType> test_data =
      TestFixture::TestData();
  Asn1Value lhs;
  Asn1Value rhs;
  for (int i = 0; i < test_data.size(); ++i) {
    ASYLO_ASSERT_OK_AND_ASSIGN(lhs, TestFixture::Create(test_data[i]));
    for (int j = 0; j < test_data.size(); ++j) {
      ASYLO_ASSERT_OK_AND_ASSIGN(rhs, TestFixture::Create(test_data[j]));

      // Eq() calls operator== and Ne() calls operator!=. We should test that
      // both operators return the correct value in each case.
      if (i == j) {
        EXPECT_THAT(lhs, Eq(rhs));
        EXPECT_THAT(lhs, Not(Ne(rhs)));
      } else {
        EXPECT_THAT(lhs, Not(Eq(rhs)));
        EXPECT_THAT(lhs, Ne(rhs));
      }
    }
  }

  std::vector<std::vector<typename TestFixture::ValueType>> equal_test_data =
      TestFixture::EqualTestData();
  for (int lhs_set = 0; lhs_set < equal_test_data.size(); ++lhs_set) {
    for (int rhs_set = 0; rhs_set < equal_test_data.size(); ++rhs_set) {
      for (int i = 0; i < equal_test_data[lhs_set].size(); ++i) {
        ASYLO_ASSERT_OK_AND_ASSIGN(
            lhs, TestFixture::Create(equal_test_data[lhs_set][i]));
        for (int j = 0; j < equal_test_data[rhs_set].size(); ++j) {
          ASYLO_ASSERT_OK_AND_ASSIGN(
              rhs, TestFixture::Create(equal_test_data[rhs_set][j]));

          // Eq() calls operator== and Ne() calls operator!=. We should test
          // that both operators return the correct value in each case.
          if (lhs_set == rhs_set) {
            EXPECT_THAT(lhs, Eq(rhs));
            EXPECT_THAT(lhs, Not(Ne(rhs)));
          } else {
            EXPECT_THAT(lhs, Not(Eq(rhs)));
            EXPECT_THAT(lhs, Ne(rhs));
          }
        }
      }
    }
  }
}

TYPED_TEST(Asn1Test, BsslGetAndCreateFromBsslRoundtripDoesntChangeValue) {
  Asn1Value original;
  Asn1Value roundtrip;
  for (const auto &value : TestFixture::TestData()) {
    ASYLO_ASSERT_OK_AND_ASSIGN(original, TestFixture::Create(value));
    typename TestFixture::BsslValueType bssl_value;
    ASYLO_ASSERT_OK_AND_ASSIGN(bssl_value, TestFixture::GetBssl(original));
    ASYLO_ASSERT_OK_AND_ASSIGN(roundtrip,
                               TestFixture::CreateFromBssl(bssl_value));
    EXPECT_THAT(roundtrip, Eq(original));
    typename TestFixture::ValueType roundtrip_value;
    ASYLO_ASSERT_OK_AND_ASSIGN(roundtrip_value, TestFixture::Get(roundtrip));
    TestFixture::ExpectEqual(roundtrip_value, value);
  }
}

TYPED_TEST(Asn1Test, BsslGetAndBsslSetRoundtripDoesntChangeValue) {
  Asn1Value original;
  Asn1Value roundtrip;
  for (const auto &value : TestFixture::TestData()) {
    ASYLO_ASSERT_OK_AND_ASSIGN(original, TestFixture::Create(value));
    typename TestFixture::BsslValueType bssl_value;
    ASYLO_ASSERT_OK_AND_ASSIGN(bssl_value, TestFixture::GetBssl(original));
    ASYLO_ASSERT_OK(TestFixture::SetBssl(&roundtrip, bssl_value));
    EXPECT_THAT(roundtrip, Eq(original));
    typename TestFixture::ValueType roundtrip_value;
    ASYLO_ASSERT_OK_AND_ASSIGN(roundtrip_value, TestFixture::Get(roundtrip));
    TestFixture::ExpectEqual(roundtrip_value, value);
  }
}

TYPED_TEST(Asn1Test, SerializedAsn1ValuesDeserializeToOriginalValues) {
  for (const auto &value : TestFixture::TestData()) {
    Asn1Value original;
    ASYLO_ASSERT_OK_AND_ASSIGN(original, TestFixture::Create(value));

    std::vector<uint8_t> der;
    ASYLO_ASSERT_OK_AND_ASSIGN(der, original.SerializeToDer());

    Asn1Value roundtrip;
    ASYLO_ASSERT_OK_AND_ASSIGN(roundtrip, Asn1Value::CreateFromDer(der));
    typename TestFixture::ValueType roundtrip_value;
    ASYLO_ASSERT_OK_AND_ASSIGN(roundtrip_value, TestFixture::Get(roundtrip));
    TestFixture::ExpectEqual(roundtrip_value, value);
  }
}

TYPED_TEST(Asn1Test, ValuesOfUnsupportedTypesHaveNulloptType) {
  Asn1Value unsupported;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      unsupported, Asn1Value::CreateFromDer(
                       absl::HexStringToBytes(kUnsupportedValueDerHex)));
  EXPECT_THAT(unsupported.Type(), Eq(absl::nullopt));
  EXPECT_THAT(TestFixture::Get(unsupported),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TYPED_TEST(Asn1Test, ValuesOfUnsupportedTypesAreNotEqualToSupportedValues) {
  Asn1Value unsupported;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      unsupported, Asn1Value::CreateFromDer(
                       absl::HexStringToBytes(kUnsupportedValueDerHex)));
  EXPECT_THAT(unsupported, Not(Eq(unsupported)));
  EXPECT_THAT(unsupported, Ne(unsupported));
  for (const auto &value : TestFixture::TestData()) {
    Asn1Value supported;
    ASYLO_ASSERT_OK_AND_ASSIGN(supported, TestFixture::Create(value));
    EXPECT_THAT(unsupported, Not(Eq(supported)));
    EXPECT_THAT(unsupported, Ne(supported));
  }
}

TYPED_TEST(Asn1Test, ValuesOfUnsupportedTypesCanBeSerialized) {
  Asn1Value unsupported;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      unsupported, Asn1Value::CreateFromDer(
                       absl::HexStringToBytes(kUnsupportedValueDerHex)));
  std::vector<uint8_t> der_roundtrip;
  ASYLO_ASSERT_OK_AND_ASSIGN(der_roundtrip, unsupported.SerializeToDer());
  EXPECT_THAT(ByteContainerView(der_roundtrip),
              ContainerEq(ByteContainerView(
                  absl::HexStringToBytes(kUnsupportedValueDerHex))));
}

}  // namespace
}  // namespace asylo
