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

#include <openssl/base.h>
#include <openssl/bn.h>

#include <cstdint>
#include <iterator>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/crypto/bignum_util.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

using ::testing::ContainerEq;
using ::testing::Eq;
using ::testing::Ne;
using ::testing::Not;
using ::testing::Optional;
using ::testing::StrEq;
using ::testing::Test;
using ::testing::Types;

// A hex string of the DER encoding of a BIT STRING value.
constexpr char kUnsupportedValueDerHex[] = "0304066e5dc0";

// Prints a BIGNUM value.
std::string PrintBignum(const BIGNUM &bignum) {
  std::pair<Sign, std::vector<uint8_t>> sign_and_bytes =
      BigEndianBytesFromBignum(bignum).ValueOrDie();
  return absl::StrCat(
      sign_and_bytes.first == Sign::kNegative ? "-" : "", "0x",
      absl::BytesToHexString(absl::string_view(
          reinterpret_cast<const char *>(sign_and_bytes.second.data()),
          sign_and_bytes.second.size())));
}

// A type to represent an Asn1Type in a Types<> invocation.
template <Asn1Type kType>
using Asn1TypeTag = std::integral_constant<Asn1Type, kType>;

// A template fixture for testing with each of the ASN.1 value types that
// Asn1Value supports. T must be an invocation of Asn1TypeTag. Each
// specialization of Asn1Test should look like:
//
//     template <>
//     class Asn1Test<Asn1TypeTag<Asn1Type::kSomeType>> : public Test {
//      public:
//       // The C++ type to use to represent owned mutable values of ASN.1 type
//       // kSomeType.
//       using ValueType = ...;
//
//       // Test data for kSomeType.
//       static std::vector<ValueType> TestData() {
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
//                              const ValueType &rhs) {
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
//     };
template <typename T>
class Asn1Test;

// Specialization of Asn1Test for Asn1Type::kBoolean.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kBoolean>> : public Test {
 public:
  using ValueType = bool;

  static std::vector<ValueType> TestData() { return {false, true}; }

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
};

// Specialization of Asn1Test for Asn1Type::kInteger.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kInteger>> : public Test {
 public:
  using ValueType = bssl::UniquePtr<BIGNUM>;

  static std::vector<ValueType> TestData() {
    bssl::UniquePtr<BIGNUM> test_data[] = {
        std::move(BignumFromInteger(0)).ValueOrDie(),
        std::move(BignumFromInteger(343)).ValueOrDie(),
        std::move(BignumFromInteger(-1729)).ValueOrDie(),
        std::move(BignumFromBigEndianBytes("0123456789abcdef")).ValueOrDie(),
        std::move(BignumFromBigEndianBytes("0123456789abcdef", Sign::kNegative))
            .ValueOrDie()};
    return std::vector<bssl::UniquePtr<BIGNUM>>(
        std::make_move_iterator(std::begin(test_data)),
        std::make_move_iterator(std::end(test_data)));
  }

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
};

// Specialization of Asn1Test for Asn1Type::kEnumerated.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kEnumerated>> : public Test {
 public:
  // ENUMERATED tests re-use functionality from INTEGER tests.
  using Base = Asn1Test<Asn1TypeTag<Asn1Type::kInteger>>;

  using ValueType = Base::ValueType;

  static std::vector<ValueType> TestData() { return Base::TestData(); }

  static std::vector<ValueType> BadTestData() { return Base::BadTestData(); }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    return Base::ExpectEqual(lhs, rhs);
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
};

// Specialization of Asn1Test for Asn1Type::kOctetString.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kOctetString>> : public Test {
 public:
  using ValueType = std::vector<uint8_t>;

  static std::vector<ValueType> TestData() {
    return {{}, {1}, {1, 1, 2, 3, 5, 8, 13, 21, 34, 55}, {4, 0, 4}};
  }

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
};

// Specialization of Asn1Test for Asn1Type::kObjectId.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kObjectId>> : public Test {
 public:
  using ValueType = std::string;

  static std::vector<ValueType> TestData() {
    return {"1.2", "1.2.840", "1.2.840.113549.1", "2.5", "2.5.8"};
  }

  static std::vector<ValueType> BadTestData() {
    return {"", "fingers", "......."};
  }

  static void ExpectEqual(const ValueType &lhs, const ValueType &rhs) {
    EXPECT_THAT(lhs, StrEq(rhs));
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
};

// Specialization of Asn1Test for Asn1Type::kSequence.
template <>
class Asn1Test<Asn1TypeTag<Asn1Type::kSequence>> : public Test {
 public:
  using ValueType = std::vector<Asn1Value>;

  static std::vector<ValueType> TestData() {
    return {{},
            {Asn1Value::CreateBoolean(false).ValueOrDie()},
            {Asn1Value::CreateOctetString("foobar").ValueOrDie(),
             Asn1Value::CreateBoolean(true).ValueOrDie(),
             Asn1Value::CreateOctetString("raboof").ValueOrDie()},
            {Asn1Value::CreateSequence(
                 {Asn1Value::CreateBoolean(true).ValueOrDie(),
                  Asn1Value::CreateBoolean(false).ValueOrDie()})
                 .ValueOrDie()}};
  }

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
};

using Asn1TestingTypes =
    Types<Asn1TypeTag<Asn1Type::kBoolean>, Asn1TypeTag<Asn1Type::kInteger>,
          Asn1TypeTag<Asn1Type::kEnumerated>,
          Asn1TypeTag<Asn1Type::kOctetString>, Asn1TypeTag<Asn1Type::kObjectId>,
          Asn1TypeTag<Asn1Type::kSequence>>;
TYPED_TEST_SUITE(Asn1Test, Asn1TestingTypes);

// std::vector<Asn1ValueType<TestParam::value>>::const_reference is used for
// iteration in the tests below because std::vector<bool>::const_iterator
// dereferences to a special bit-view class, not to bool or const bool &.

TYPED_TEST(Asn1Test, CreateCreatesAsn1ValueWithCorrectTypeAndValue) {
  Asn1Value asn1;
  for (const auto &value : TestFixture::TestData()) {
    ASYLO_ASSERT_OK_AND_ASSIGN(asn1, TestFixture::Create(value));
    EXPECT_THAT(asn1.Type(), Optional(TypeParam::value));

    typename TestFixture::ValueType roundtrip;
    ASYLO_ASSERT_OK_AND_ASSIGN(roundtrip, TestFixture::Get(asn1));
    TestFixture::ExpectEqual(roundtrip, value);
  }
}

TYPED_TEST(Asn1Test, CreateFailsWithBadInputs) {
  for (const auto &value : TestFixture::BadTestData()) {
    EXPECT_THAT(TestFixture::Create(value).status(),
                StatusIs(error::GoogleError::INVALID_ARGUMENT));
  }
}

TYPED_TEST(Asn1Test, SetterSetsAsn1ValueToHaveCorrectTypeAndValue) {
  Asn1Value asn1;
  for (const auto &value : TestFixture::TestData()) {
    ASYLO_ASSERT_OK(TestFixture::Set(&asn1, value));
    EXPECT_THAT(asn1.Type(), Optional(TypeParam::value));

    typename TestFixture::ValueType roundtrip;
    ASYLO_ASSERT_OK_AND_ASSIGN(roundtrip, TestFixture::Get(asn1));
    TestFixture::ExpectEqual(roundtrip, value);
  }
}

TYPED_TEST(Asn1Test, SetterFailsWithBadInputs) {
  Asn1Value asn1;
  for (const auto &value : TestFixture::BadTestData()) {
    EXPECT_THAT(TestFixture::Set(&asn1, value),
                StatusIs(error::GoogleError::INVALID_ARGUMENT));
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

TYPED_TEST(Asn1Test,
           Asn1ValuesOfSameTypeCompareEqualIfAndOnlyIfConstructedFromSameData) {
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
  EXPECT_THAT(TestFixture::Get(unsupported).status(),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
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
