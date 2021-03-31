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

#ifndef ASYLO_CRYPTO_ASN1_SCHEMA_H_
#define ASYLO_CRYPTO_ASN1_SCHEMA_H_

#include <cstddef>
#include <limits>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/asn1.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

// A schema for ASN.1 values. An Asn1Schema implementation can convert between
// an Asn1Value matching the schema and a given ValueTypeT.
//
// See the schemas below for examples of how to compose implementations of
// Asn1Schema to create schemas that recognize complex ASN.1 structures.
template <typename ValueTypeT>
class Asn1Schema {
 public:
  // The type that the schema uses to represent matching values.
  using ValueType = ValueTypeT;

  virtual ~Asn1Schema() = default;

  // Reads a matching value from |asn1| or returns an error if |asn1| does not
  // match the schema.
  virtual StatusOr<ValueType> Read(const Asn1Value &asn1) const = 0;

  // Writes |value| to an Asn1Value.
  virtual StatusOr<Asn1Value> Write(const ValueType &value) const = 0;
};

namespace internal {

// The schema returned by Asn1Sequence(). See the documentation of
// Asn1Sequence() for an explanation of Asn1SequenceImpl's behavior.
template <typename FirstValueTypeT, typename SecondValueTypeT>
class Asn1SequenceImpl
    : public Asn1Schema<std::tuple<FirstValueTypeT, SecondValueTypeT>> {
 public:
  // Creates an Asn1SequenceImpl that uses |first_schema| to read and write the
  // first sequence element and |second_schema| to read and write the second
  // sequence element.
  Asn1SequenceImpl(std::unique_ptr<Asn1Schema<FirstValueTypeT>> first_schema,
                   std::unique_ptr<Asn1Schema<SecondValueTypeT>> second_schema)
      : first_schema_(std::move(first_schema)),
        second_schema_(std::move(second_schema)) {}

  // From Asn1Schema.
  StatusOr<std::tuple<FirstValueTypeT, SecondValueTypeT>> Read(
      const Asn1Value &asn1) const override {
    std::vector<Asn1Value> elements;
    ASYLO_ASSIGN_OR_RETURN(elements, asn1.GetSequence());
    if (elements.size() != 2) {
      return Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrFormat("Sequence has size %d, but size 2 was expected",
                          elements.size()));
    }
    std::tuple<FirstValueTypeT, SecondValueTypeT> value;
    ASYLO_ASSIGN_OR_RETURN(std::get<0>(value),
                           first_schema_->Read(elements[0]));
    ASYLO_ASSIGN_OR_RETURN(std::get<1>(value),
                           second_schema_->Read(elements[1]));
    return value;
  }

  // From Asn1Schema.
  StatusOr<Asn1Value> Write(
      const std::tuple<FirstValueTypeT, SecondValueTypeT> &value) const {
    std::vector<Asn1Value> elements(2);
    ASYLO_ASSIGN_OR_RETURN(elements[0],
                           first_schema_->Write(std::get<0>(value)));
    ASYLO_ASSIGN_OR_RETURN(elements[1],
                           second_schema_->Write(std::get<1>(value)));
    return Asn1Value::CreateSequence(elements);
  }

 private:
  std::unique_ptr<Asn1Schema<FirstValueTypeT>> first_schema_;
  std::unique_ptr<Asn1Schema<SecondValueTypeT>> second_schema_;
};

// The schema returned by Asn1SequenceOf(). See the documentation of
// Asn1SequenceOf() for an explanation of Asn1SequenceOfImpl's behavior.
template <typename ValueTypeT>
class Asn1SequenceOfImpl : public Asn1Schema<std::vector<ValueTypeT>> {
 public:
  // Constructs an Asn1SequenceOfImpl for sequences of elements matching
  // |schema| with a size between |min_size| and |max_size|, inclusive.
  explicit Asn1SequenceOfImpl(std::unique_ptr<Asn1Schema<ValueTypeT>> schema,
                              size_t min_size, size_t max_size)
      : element_schema_(std::move(schema)),
        min_size_(min_size),
        max_size_(max_size) {}

  // From Asn1Schema.
  StatusOr<std::vector<ValueTypeT>> Read(const Asn1Value &asn1) const override {
    std::vector<Asn1Value> elements;
    ASYLO_ASSIGN_OR_RETURN(elements, asn1.GetSequence());
    ASYLO_RETURN_IF_ERROR(VerifySize(elements.size()));
    std::vector<ValueTypeT> result(elements.size());
    for (int i = 0; i < elements.size(); ++i) {
      ASYLO_ASSIGN_OR_RETURN(result[i], element_schema_->Read(elements[i]));
    }
    return result;
  }

  // From Asn1Schema.
  StatusOr<Asn1Value> Write(
      const std::vector<ValueTypeT> &value) const override {
    ASYLO_RETURN_IF_ERROR(VerifySize(value.size()));
    std::vector<Asn1Value> elements(value.size());
    for (int i = 0; i < value.size(); ++i) {
      ASYLO_ASSIGN_OR_RETURN(elements[i], element_schema_->Write(value[i]));
    }
    return Asn1Value::CreateSequence(elements);
  }

 private:
  // Returns an error if |size| is not within the limits passed at construction.
  Status VerifySize(size_t size) const {
    if (size < min_size_ || size > max_size_) {
      return Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrFormat(
              "Sequence has size %d, but a size between %d and %d was expected",
              size, min_size_, max_size_));
    }
    return absl::OkStatus();
  }

  std::unique_ptr<Asn1Schema<ValueTypeT>> element_schema_;
  size_t min_size_;
  size_t max_size_;
};

// The schema returned by NamedSchema(). See the documentation of NamedSchema()
// for an explanation of NamedSchemaImpl's behavior.
template <typename ValueTypeT>
class NamedSchemaImpl : public Asn1Schema<ValueTypeT> {
 public:
  // Constructs a NamedSchemaImpl wrapping |schema| but adding |name| as context
  // to error messages.
  NamedSchemaImpl(std::string name,
                  std::unique_ptr<Asn1Schema<ValueTypeT>> schema)
      : name_(std::move(name)), schema_(std::move(schema)) {}

  // From Asn1Schema.
  StatusOr<ValueTypeT> Read(const Asn1Value &asn1) const override {
    return WithContext(schema_->Read(asn1),
                       absl::StrFormat("Failed to read %s", name_));
  }

  // From Asn1Schema.
  StatusOr<Asn1Value> Write(const ValueTypeT &value) const override {
    return WithContext(schema_->Write(value),
                       absl::StrFormat("Failed to write %s", name_));
  }

 private:
  std::string name_;
  std::unique_ptr<Asn1Schema<ValueTypeT>> schema_;
};

}  // namespace internal

// Returns an ASN.1 schema that matches any ASN.1 value. This is useful if the
// expected type of a value needs to be determined from context, for instance
// from an OBJECT IDENTIFIER elsewhere in the containing schema.
std::unique_ptr<Asn1Schema<Asn1Value>> Asn1Any();

// Returns an ASN.1 schema that matches any OBJECT IDENTIFIER value.
std::unique_ptr<Asn1Schema<ObjectId>> Asn1ObjectId();

// Returns an ASN.1 schema that matches a SEQUENCE of elements matching the
// argument schemas in order. Currently only supports two arguments.
//
// Example:
//
//     ObjectId oid = ...;
//     std::vector<Asn1Value> elements(2);
//     ASYLO_ASSERT_OK_AND_ASSIGN(elements[0], Asn1Value::CreateObjectId(oid));
//     ASYLO_ASSERT_OK_AND_ASSIGN(elements[1], Asn1Value::CreateBoolean(true));
//     Asn1Value asn1;
//     ASYLO_ASSERT_OK_AND_ASSIGN(asn1, Asn1Value::CreateSequence(elements));
//
//     std::tuple<ObjectId, Asn1Value> read_result;
//     ASYLO_ASSERT_OK_AND_ASSIGN(
//         read_result,
//         Asn1Sequence(Asn1ObjectId(), Asn1Any())->Read(asn1));
//     EXPECT_THAT(std::get<0>(read_result), Eq(oid));
//     EXPECT_THAT(std::get<1>(read_result).GetBoolean(), IsOkAndHolds(true));
template <typename FirstValueTypeT, typename SecondValueTypeT>
std::unique_ptr<Asn1Schema<std::tuple<FirstValueTypeT, SecondValueTypeT>>>
Asn1Sequence(std::unique_ptr<Asn1Schema<FirstValueTypeT>> first_schema,
             std::unique_ptr<Asn1Schema<SecondValueTypeT>> second_schema) {
  return absl::make_unique<
      internal::Asn1SequenceImpl<FirstValueTypeT, SecondValueTypeT>>(
      std::move(first_schema), std::move(second_schema));
}

// Returns an ASN.1 schema that matches a SEQUENCE of values matching |schema|
// with a length between |min_size| and |max_size|, inclusive.
//
// If |min_size| > |max_size|, then Asn1SequenceOf() returns nullptr.
template <typename ValueTypeT>
std::unique_ptr<Asn1Schema<std::vector<ValueTypeT>>> Asn1SequenceOf(
    std::unique_ptr<Asn1Schema<ValueTypeT>> schema, size_t min_size = 0,
    size_t max_size = std::numeric_limits<size_t>::max()) {
  if (min_size > max_size) {
    return nullptr;
  }
  return absl::make_unique<internal::Asn1SequenceOfImpl<ValueTypeT>>(
      std::move(schema), min_size, max_size);
}

// Returns an ASN.1 schema that matches the same ASN.1 values as |schema| but
// adds |name| as context to all error messages from |schema|.
template <typename ValueTypeT>
std::unique_ptr<Asn1Schema<ValueTypeT>> NamedSchema(
    std::string name, std::unique_ptr<Asn1Schema<ValueTypeT>> schema) {
  return absl::make_unique<internal::NamedSchemaImpl<ValueTypeT>>(
      std::move(name), std::move(schema));
}

}  // namespace asylo

#endif  // ASYLO_CRYPTO_ASN1_SCHEMA_H_
