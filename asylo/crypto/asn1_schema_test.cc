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

#include "asylo/crypto/asn1_schema.h"

#include <openssl/nid.h>

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/crypto/asn1.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsNull;
using ::testing::Not;
using ::testing::SizeIs;

// The schema returned by FailSchema().
template <typename ValueTypeT>
class FailSchemaImpl : public Asn1Schema<ValueTypeT> {
 public:
  // Constructs a FailSchemaImpl whose methods always fail with |error|.
  explicit FailSchemaImpl(Status error) : error_(std::move(error)) {}

  // From Asn1Schema.
  StatusOr<ValueTypeT> Read(const Asn1Value & /*asn1*/) const override {
    return error_;
  }

  // From Asn1Schema.
  StatusOr<Asn1Value> Write(const ValueTypeT & /*value*/) const override {
    return error_;
  }

 private:
  Status error_;
};

// Returns an ASN.1 schema whose Read() and Write() methods always fail with
// |error|.
template <typename ValueTypeT>
std::unique_ptr<Asn1Schema<ValueTypeT>> FailSchema(Status error) {
  return absl::make_unique<FailSchemaImpl<ValueTypeT>>(std::move(error));
}

TEST(Asn1SchemaTest, Asn1AnyReadAndWriteValidValues) {
  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateBoolean(true));
  EXPECT_THAT(Asn1Any()->Read(asn1), IsOkAndHolds(asn1));
  EXPECT_THAT(Asn1Any()->Write(asn1), IsOkAndHolds(asn1));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateIntegerFromInt(-99));
  EXPECT_THAT(Asn1Any()->Read(asn1), IsOkAndHolds(asn1));
  EXPECT_THAT(Asn1Any()->Write(asn1), IsOkAndHolds(asn1));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateOctetString("foobar"));
  EXPECT_THAT(Asn1Any()->Read(asn1), IsOkAndHolds(asn1));
  EXPECT_THAT(Asn1Any()->Write(asn1), IsOkAndHolds(asn1));
}

TEST(Asn1SchemaTest, Asn1ObjectIdReadValidValues) {
  ObjectId some_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(some_oid, ObjectId::CreateFromNumericId(NID_md5));
  ObjectId other_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(other_oid, ObjectId::CreateFromNumericId(NID_rsa));

  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateObjectId(some_oid));
  EXPECT_THAT(Asn1ObjectId()->Read(asn1), IsOkAndHolds(some_oid));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateObjectId(other_oid));
  EXPECT_THAT(Asn1ObjectId()->Read(asn1), IsOkAndHolds(other_oid));
}

TEST(Asn1SchemaTest, Asn1ObjectIdReadInvalidValues) {
  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateBoolean(false));
  EXPECT_THAT(Asn1ObjectId()->Read(asn1),
              StatusIs(absl::StatusCode::kInvalidArgument));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateIntegerFromInt(-7));
  EXPECT_THAT(Asn1ObjectId()->Read(asn1),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Asn1SchemaTest, Asn1ObjectIdWriteValidValues) {
  ObjectId some_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(some_oid, ObjectId::CreateFromNumericId(NID_md5));
  ObjectId other_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(other_oid, ObjectId::CreateFromNumericId(NID_rsa));

  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1ObjectId()->Write(some_oid));
  EXPECT_THAT(asn1.GetObjectId(), IsOkAndHolds(some_oid));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1ObjectId()->Write(other_oid));
  EXPECT_THAT(asn1.GetObjectId(), IsOkAndHolds(other_oid));
}

TEST(Asn1SchemaTest, Asn1SequenceReadValidValues) {
  ObjectId some_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(some_oid, ObjectId::CreateFromNumericId(NID_md5));

  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateSequenceFromStatusOrs(
                                       {Asn1Value::CreateObjectId(some_oid),
                                        Asn1Value::CreateBoolean(true)}));
  std::tuple<ObjectId, Asn1Value> value;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      value, Asn1Sequence(Asn1ObjectId(), Asn1Any())->Read(asn1));
  EXPECT_THAT(std::get<0>(value), Eq(some_oid));
  EXPECT_THAT(std::get<1>(value).GetBoolean(), IsOkAndHolds(true));
}

TEST(Asn1SchemaTest, Asn1SequenceReadInvalidValues) {
  ObjectId some_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(some_oid, ObjectId::CreateFromNumericId(NID_md5));

  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateObjectId(some_oid));
  EXPECT_THAT(Asn1Sequence(Asn1ObjectId(), Asn1ObjectId())->Read(asn1),
              StatusIs(absl::StatusCode::kInvalidArgument));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateSequenceFromStatusOrs(
                                       {Asn1Value::CreateObjectId(some_oid)}));
  EXPECT_THAT(Asn1Sequence(Asn1ObjectId(), Asn1ObjectId())->Read(asn1),
              StatusIs(absl::StatusCode::kInvalidArgument));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateSequenceFromStatusOrs(
                                       {Asn1Value::CreateIntegerFromInt(55),
                                        Asn1Value::CreateBoolean(false)}));
  EXPECT_THAT(Asn1Sequence(Asn1ObjectId(), Asn1ObjectId())->Read(asn1),
              StatusIs(absl::StatusCode::kInvalidArgument));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateSequenceFromStatusOrs(
                                       {Asn1Value::CreateObjectId(some_oid),
                                        Asn1Value::CreateIntegerFromInt(55)}));
  EXPECT_THAT(Asn1Sequence(Asn1ObjectId(), Asn1ObjectId())->Read(asn1),
              StatusIs(absl::StatusCode::kInvalidArgument));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateSequenceFromStatusOrs(
                                       {Asn1Value::CreateIntegerFromInt(55),
                                        Asn1Value::CreateObjectId(some_oid)}));
  EXPECT_THAT(Asn1Sequence(Asn1ObjectId(), Asn1ObjectId())->Read(asn1),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(Asn1SchemaTest, Asn1SequenceWriteValidValues) {
  ObjectId some_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(some_oid, ObjectId::CreateFromNumericId(NID_md5));

  Asn1Value any;
  ASYLO_ASSERT_OK_AND_ASSIGN(any, Asn1Value::CreateBoolean(true));
  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Sequence(Asn1ObjectId(), Asn1Any())
                                       ->Write(std::make_tuple(some_oid, any)));
  std::vector<Asn1Value> elements;
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, asn1.GetSequence());
  ASSERT_THAT(elements, SizeIs(2));
  EXPECT_THAT(elements[0].GetObjectId(), IsOkAndHolds(some_oid));
  EXPECT_THAT(elements[1].GetBoolean(), IsOkAndHolds(true));
}

TEST(Asn1SchemaTest, Asn1SequenceWriteInvalidValues) {
  Status status(absl::StatusCode::kFailedPrecondition, "bazzle");
  EXPECT_THAT(Asn1Sequence(Asn1Any(), FailSchema<int>(status))
                  ->Write(std::make_tuple(Asn1Value(), 5))
                  .status(),
              Eq(status));
}

TEST(Asn1SchemaTest, Asn1SequenceOfReturnsNullptrIfMinSizeExceedsMaxSize) {
  constexpr int kMaxSizeParameter = 20;

  for (int min_size = 0; min_size <= kMaxSizeParameter; ++min_size) {
    for (int max_size = 0; max_size <= kMaxSizeParameter; ++max_size) {
      if (min_size <= max_size) {
        EXPECT_THAT(Asn1SequenceOf(Asn1ObjectId(), min_size, max_size),
                    Not(IsNull()));
      } else {
        EXPECT_THAT(Asn1SequenceOf(Asn1ObjectId(), min_size, max_size),
                    IsNull());
      }
    }
  }
}

TEST(Asn1SchemaTest, Asn1SequenceOfReadValidValues) {
  constexpr int kMaxTestSequenceElements = 20;

  ObjectId some_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(some_oid, ObjectId::CreateFromNumericId(NID_md5));

  Asn1Value asn1;
  for (int i = 0; i <= kMaxTestSequenceElements; ++i) {
    ASYLO_ASSERT_OK_AND_ASSIGN(
        asn1,
        Asn1Value::CreateSequenceFromStatusOrs(std::vector<StatusOr<Asn1Value>>(
            i, Asn1Value::CreateObjectId(some_oid))));
    EXPECT_THAT(
        Asn1SequenceOf(Asn1ObjectId())->Read(asn1),
        IsOkAndHolds(ElementsAreArray(std::vector<ObjectId>(i, some_oid))));
  }
  for (int i = 3; i <= kMaxTestSequenceElements; ++i) {
    ASYLO_ASSERT_OK_AND_ASSIGN(
        asn1,
        Asn1Value::CreateSequenceFromStatusOrs(std::vector<StatusOr<Asn1Value>>(
            i, Asn1Value::CreateObjectId(some_oid))));
    EXPECT_THAT(
        Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/3)->Read(asn1),
        IsOkAndHolds(ElementsAreArray(std::vector<ObjectId>(i, some_oid))));
  }
  for (int i = 0; i <= 3; ++i) {
    ASYLO_ASSERT_OK_AND_ASSIGN(
        asn1,
        Asn1Value::CreateSequenceFromStatusOrs(std::vector<StatusOr<Asn1Value>>(
            i, Asn1Value::CreateObjectId(some_oid))));
    EXPECT_THAT(
        Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/0,
                       /*max_size=*/3)
            ->Read(asn1),
        IsOkAndHolds(ElementsAreArray(std::vector<ObjectId>(i, some_oid))));
  }
  ASYLO_ASSERT_OK_AND_ASSIGN(
      asn1,
      Asn1Value::CreateSequenceFromStatusOrs(std::vector<StatusOr<Asn1Value>>(
          3, Asn1Value::CreateObjectId(some_oid))));
  EXPECT_THAT(Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/3,
                             /*max_size=*/3)
                  ->Read(asn1),
              IsOkAndHolds(ElementsAre(some_oid, some_oid, some_oid)));
}

TEST(Asn1SchemaTest, Asn1SequenceOfReadInvalidValues) {
  constexpr int kMaxTestSequenceElements = 20;

  ObjectId some_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(some_oid, ObjectId::CreateFromNumericId(NID_md5));

  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateSequenceFromStatusOrs(
                                       {Asn1Value::CreateIntegerFromInt(12)}));
  EXPECT_THAT(Asn1SequenceOf(Asn1ObjectId())->Read(asn1),
              StatusIs(absl::StatusCode::kInvalidArgument));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateSequenceFromStatusOrs(
                                       {Asn1Value::CreateObjectId(some_oid),
                                        Asn1Value::CreateIntegerFromInt(-1),
                                        Asn1Value::CreateObjectId(some_oid)}));
  EXPECT_THAT(Asn1SequenceOf(Asn1ObjectId())->Read(asn1),
              StatusIs(absl::StatusCode::kInvalidArgument));

  for (int i = 0; i < 3; ++i) {
    ASYLO_ASSERT_OK_AND_ASSIGN(
        asn1,
        Asn1Value::CreateSequenceFromStatusOrs(std::vector<StatusOr<Asn1Value>>(
            i, Asn1Value::CreateObjectId(some_oid))));
    EXPECT_THAT(Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/3)->Read(asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  for (int i = 4; i <= kMaxTestSequenceElements; ++i) {
    ASYLO_ASSERT_OK_AND_ASSIGN(
        asn1,
        Asn1Value::CreateSequenceFromStatusOrs(std::vector<StatusOr<Asn1Value>>(
            i, Asn1Value::CreateObjectId(some_oid))));
    EXPECT_THAT(Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/0,
                               /*max_size=*/3)
                    ->Read(asn1),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  for (int i = 0; i <= kMaxTestSequenceElements; ++i) {
    if (i != 3) {
      ASYLO_ASSERT_OK_AND_ASSIGN(
          asn1, Asn1Value::CreateSequenceFromStatusOrs(
                    std::vector<StatusOr<Asn1Value>>(
                        i, Asn1Value::CreateObjectId(some_oid))));
      EXPECT_THAT(Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/3,
                                 /*max_size=*/3)
                      ->Read(asn1),
                  StatusIs(absl::StatusCode::kInvalidArgument));
    }
  }
}

TEST(Asn1SchemaTest, Asn1SequenceOfWriteValidValues) {
  constexpr int kMaxTestSequenceElements = 20;

  ObjectId some_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(some_oid, ObjectId::CreateFromNumericId(NID_md5));

  Asn1Value asn1;
  std::vector<Asn1Value> elements;
  for (int i = 0; i <= kMaxTestSequenceElements; ++i) {
    ASYLO_ASSERT_OK_AND_ASSIGN(asn1,
                               Asn1SequenceOf(Asn1ObjectId())
                                   ->Write(std::vector<ObjectId>(i, some_oid)));
    ASYLO_ASSERT_OK_AND_ASSIGN(elements, asn1.GetSequence());
    ASSERT_THAT(elements, SizeIs(i));
    for (const auto &element : elements) {
      EXPECT_THAT(element.GetObjectId(), IsOkAndHolds(some_oid));
    }
  }
  for (int i = 3; i <= kMaxTestSequenceElements; ++i) {
    ASYLO_ASSERT_OK_AND_ASSIGN(asn1,
                               Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/3)
                                   ->Write(std::vector<ObjectId>(i, some_oid)));
    ASYLO_ASSERT_OK_AND_ASSIGN(elements, asn1.GetSequence());
    ASSERT_THAT(elements, SizeIs(i));
    for (const auto &element : elements) {
      EXPECT_THAT(element.GetObjectId(), IsOkAndHolds(some_oid));
    }
  }
  for (int i = 0; i <= 3; ++i) {
    ASYLO_ASSERT_OK_AND_ASSIGN(
        asn1, Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/0, /*max_size=*/3)
                  ->Write(std::vector<ObjectId>(i, some_oid)));
    ASYLO_ASSERT_OK_AND_ASSIGN(elements, asn1.GetSequence());
    ASSERT_THAT(elements, SizeIs(i));
    for (const auto &element : elements) {
      EXPECT_THAT(element.GetObjectId(), IsOkAndHolds(some_oid));
    }
  }
  ASYLO_ASSERT_OK_AND_ASSIGN(
      asn1, Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/3, /*max_size=*/3)
                ->Write({some_oid, some_oid, some_oid}));
  ASYLO_ASSERT_OK_AND_ASSIGN(elements, asn1.GetSequence());
  ASSERT_THAT(elements, SizeIs(3));
  for (const auto &element : elements) {
    EXPECT_THAT(element.GetObjectId(), IsOkAndHolds(some_oid));
  }
}

TEST(Asn1SchemaTest, Asn1SequenceOfWriteInvalidValues) {
  constexpr int kMaxTestSequenceElements = 20;

  ObjectId some_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(some_oid, ObjectId::CreateFromNumericId(NID_md5));
  Status status(absl::StatusCode::kDataLoss, "foobar");

  EXPECT_THAT(Asn1SequenceOf(FailSchema<int>(status))->Write({4}).status(),
              Eq(status));

  for (int i = 0; i < 3; ++i) {
    EXPECT_THAT(Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/3)
                    ->Write(std::vector<ObjectId>(i, some_oid)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  for (int i = 4; i <= kMaxTestSequenceElements; ++i) {
    EXPECT_THAT(Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/0, /*max_size=*/3)
                    ->Write(std::vector<ObjectId>(i, some_oid)),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  for (int i = 0; i <= kMaxTestSequenceElements; ++i) {
    if (i != 3) {
      EXPECT_THAT(Asn1SequenceOf(Asn1ObjectId(), /*min_size=*/3, /*max_size=*/3)
                      ->Write(std::vector<ObjectId>(i, some_oid)),
                  StatusIs(absl::StatusCode::kInvalidArgument));
    }
  }
}

TEST(Asn1SchemaTest, NamedSchemaReadValidValues) {
  ObjectId some_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(some_oid, ObjectId::CreateFromNumericId(NID_md5));

  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateBoolean(true));
  EXPECT_THAT(NamedSchema("ANY", Asn1Any())->Read(asn1), IsOkAndHolds(asn1));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateObjectId(some_oid));
  EXPECT_THAT(NamedSchema("OBJECT IDENTIFIER", Asn1ObjectId())->Read(asn1),
              IsOkAndHolds(some_oid));
}

TEST(Asn1SchemaTest, NamedSchemaReadInvalidValues) {
  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateOctetString("bad"));
  auto oid_read_result =
      NamedSchema("OBJECT IDENTIFIER", Asn1ObjectId())->Read(asn1);
  EXPECT_THAT(oid_read_result,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to read OBJECT IDENTIFIER")));

  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateBoolean(false));
  auto sequence_read_result =
      NamedSchema("SEQUENCE OF ANY", Asn1SequenceOf(Asn1Any()))->Read(asn1);
  EXPECT_THAT(sequence_read_result,
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to read SEQUENCE OF ANY")));
}

TEST(Asn1SchemaTest, NamedSchemaWriteValidValues) {
  ObjectId some_oid;
  ASYLO_ASSERT_OK_AND_ASSIGN(some_oid, ObjectId::CreateFromNumericId(NID_md5));

  Asn1Value base;
  ASYLO_ASSERT_OK_AND_ASSIGN(base, Asn1Value::CreateBoolean(true));
  Asn1Value asn1;
  ASYLO_ASSERT_OK_AND_ASSIGN(asn1, NamedSchema("ANY", Asn1Any())->Write(base));
  EXPECT_THAT(asn1.GetBoolean(), IsOkAndHolds(true));

  ASYLO_ASSERT_OK_AND_ASSIGN(
      asn1, NamedSchema("OBJECT IDENTIFIER", Asn1ObjectId())->Write(some_oid));
  EXPECT_THAT(asn1.GetObjectId(), IsOkAndHolds(some_oid));
}

TEST(Asn1SchemaTest, NamedSchemaWriteInvalidValues) {
  Status expected(absl::StatusCode::kUnavailable, "barfoo");

  auto write_result = NamedSchema("Fail", FailSchema<int>(expected))->Write(12);
  EXPECT_THAT(write_result,
              StatusIs(expected.code(), HasSubstr("Failed to write Fail")));
}

}  // namespace
}  // namespace asylo
