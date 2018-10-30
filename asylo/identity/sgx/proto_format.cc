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

#include "asylo/identity/sgx/proto_format.h"

#include <memory>
#include <vector>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/text_format.h>
#include "absl/strings/escaping.h"
#include "absl/strings/str_join.h"
#include "absl/memory/memory.h"
#include "asylo/identity/sgx/secs_attributes.h"
#include "asylo/identity/util/bit_vector_128.pb.h"
#include "asylo/identity/util/sha256_hash.pb.h"

namespace asylo {
namespace sgx {
namespace {

using google::protobuf::TextFormat;

// A FieldValuePrinter that prints a bytes field in hex.
class BytesPrinter : public TextFormat::FastFieldValuePrinter {
 public:
  void PrintBytes(const std::string &value,
                  TextFormat::BaseTextGenerator *generator) const override {
    generator->PrintString(absl::BytesToHexString(value));
  }
};

// A FieldValuePrinter that prints the name of each ATTRIBUTE bit that is set in
// the lower 64 bits of ATTRIBUTES.
class AttributesLowPrinter : public TextFormat::FastFieldValuePrinter {
 public:
  void PrintUInt64(uint64_t value,
                   TextFormat::BaseTextGenerator *generator) const override {
    BitVector128 attributes;
    attributes.set_low(value);
    attributes.set_high(0);

    generator->PrintLiteral("[");

    std::vector<std::string> printable_attributes;
    GetPrintableAttributeList(attributes, &printable_attributes);
    generator->PrintString(absl::StrJoin(printable_attributes, ", "));

    generator->PrintLiteral("]");
  }
};

// A FieldValuePrinter that prints the name of each ATTRIBUTE bit that is set in
// the upper 64 bits of ATTRIBUTES.
class AttributesHighPrinter : public TextFormat::FastFieldValuePrinter {
 public:
  void PrintUInt64(uint64_t value,
                   TextFormat::BaseTextGenerator *generator) const override {
    BitVector128 attributes;
    attributes.set_low(0);
    attributes.set_high(value);

    generator->PrintLiteral("[");

    std::vector<std::string> printable_attributes;
    GetPrintableAttributeList(attributes, &printable_attributes);
    generator->PrintString(absl::StrJoin(printable_attributes, ", "));

    generator->PrintLiteral("]");
  }
};

std::unique_ptr<TextFormat::Printer> CreateSgxCodeIdentityPrinter() {
  auto printer = absl::make_unique<TextFormat::Printer>();
  const google::protobuf::Descriptor *descriptor = BitVector128::descriptor();

  // Register a special printer for the fields that make up the enclave's
  // ATTRIBUTES. The printer prints the name of each ATTRIBUTE bit that is set.
  printer->RegisterFieldValuePrinter(descriptor->FindFieldByName("low"),
                                     new AttributesLowPrinter());
  printer->RegisterFieldValuePrinter(descriptor->FindFieldByName("high"),
                                     new AttributesHighPrinter());

  // Register a special printer for the Sha256Hash proto that prints the hash
  // value in hex.
  descriptor = Sha256HashProto::descriptor();
  printer->RegisterFieldValuePrinter(descriptor->FindFieldByName("hash"),
                                     new BytesPrinter());

  return printer;
}

std::string FormatProto(const google::protobuf::Message &message) {
  static const TextFormat::Printer *printer =
      CreateSgxCodeIdentityPrinter().release();

  std::string text;
  printer->PrintToString(message, &text);
  return text;
}

}  // namespace

std::string FormatCodeIdentityProto(const CodeIdentity &code_identity) {
  return FormatProto(code_identity);
}

std::string FormatCodeIdentityMatchSpecProto(
    const CodeIdentityMatchSpec &match_spec) {
  return FormatProto(match_spec);
}

std::string FormatCodeIdentityExpectationProto(
    const CodeIdentityExpectation &expectation) {
  return FormatProto(expectation);
}

}  // namespace sgx
}  // namespace asylo
