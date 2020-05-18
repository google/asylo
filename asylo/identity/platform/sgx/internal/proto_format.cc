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

#include "asylo/identity/platform/sgx/internal/proto_format.h"

#include <memory>
#include <vector>

#include <google/protobuf/descriptor.h>
#include <google/protobuf/text_format.h>
#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/identity/platform/sgx/attributes_util.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/platform/sgx/miscselect.pb.h"
#include "asylo/identity/platform/sgx/miscselect_util.h"

namespace asylo {
namespace sgx {
namespace {

using google::protobuf::TextFormat;

void PrintAttributes(const Attributes &attributes,
                     TextFormat::BaseTextGenerator *generator) {
  generator->PrintLiteral("[");
  generator->PrintString(
      absl::StrJoin(GetPrintableAttributeList(attributes), ", "));
  generator->PrintLiteral("]");
}

// A FieldValuePrinter that prints a bytes field in hex.
class BytesPrinter : public TextFormat::FastFieldValuePrinter {
 public:
  void PrintBytes(const std::string &value,
                  TextFormat::BaseTextGenerator *generator) const override {
    generator->PrintLiteral("0x");
    generator->PrintString(absl::BytesToHexString(value));
  }
};

// A FieldValuePrinter that prints the name of each ATTRIBUTE bit that is set in
// the lower 64 bits of ATTRIBUTES (the flags bits).
class AttributesFlagsPrinter : public TextFormat::FastFieldValuePrinter {
 public:
  void PrintUInt64(uint64_t value,
                   TextFormat::BaseTextGenerator *generator) const override {
    Attributes attributes;
    attributes.set_flags(value);
    attributes.set_xfrm(0);
    PrintAttributes(attributes, generator);
  }
};

// A FieldValuePrinter that prints the name of each ATTRIBUTE bit that is set in
// the upper 64 bits of ATTRIBUTES (the XFRM bits).
class AttributesXfrmPrinter : public TextFormat::FastFieldValuePrinter {
 public:
  void PrintUInt64(uint64_t value,
                   TextFormat::BaseTextGenerator *generator) const override {
    Attributes attributes;
    attributes.set_flags(0);
    attributes.set_xfrm(value);
    PrintAttributes(attributes, generator);
  }
};

// A FieldValuePrinter that prints the name of each MISCSELECT bit that is set
// in the MISCSELECT bit vector.
class MiscSelectPrinter : public TextFormat::FastFieldValuePrinter {
 public:
  void PrintUInt32(uint32_t value,
                   TextFormat::BaseTextGenerator *generator) const override {
  generator->PrintLiteral("[");
  generator->PrintString(
      absl::StrJoin(GetPrintableMiscselectList(value), ", "));
  generator->PrintLiteral("]");
  }
};

std::unique_ptr<TextFormat::Printer> CreateSgxProtoPrinter() {
  auto printer = absl::make_unique<TextFormat::Printer>();
  const google::protobuf::Descriptor *descriptor = Attributes::descriptor();

  // Register a special printer for the fields that make up the enclave's
  // ATTRIBUTES. The printer prints the name of each attribute bit that is set.
  printer->RegisterFieldValuePrinter(descriptor->FindFieldByName("flags"),
                                     new AttributesFlagsPrinter());
  printer->RegisterFieldValuePrinter(descriptor->FindFieldByName("xfrm"),
                                     new AttributesXfrmPrinter());

  // Register a special printer for the Sha256Hash proto that prints the hash
  // value in hex.
  descriptor = Sha256HashProto::descriptor();
  printer->RegisterFieldValuePrinter(descriptor->FindFieldByName("hash"),
                                     new BytesPrinter());

  // Register a special printer for Miscselect protos that prints the name of
  // each value in the MISCSELECT bit vector that is set.
  descriptor = Miscselect::descriptor();
  printer->RegisterFieldValuePrinter(descriptor->FindFieldByName("value"),
                                     new MiscSelectPrinter());

  // CodeIdentity and CodeIdentityMatchSpec define MISCSELECT as a uint32 field
  // rather than as a Miscselect message. Update these fields to use the special
  // Miscselect printer.
  descriptor = CodeIdentity::descriptor();
  printer->RegisterFieldValuePrinter(descriptor->FindFieldByName("miscselect"),
                                     new MiscSelectPrinter());
  descriptor = CodeIdentityMatchSpec::descriptor();
  printer->RegisterFieldValuePrinter(
      descriptor->FindFieldByName("miscselect_match_mask"),
                                     new MiscSelectPrinter());

  // Print CPUSVN as a hex string rather than raw bytes.
  descriptor = CpuSvn::descriptor();
  printer->RegisterFieldValuePrinter(descriptor->FindFieldByName("value"),
                                     new BytesPrinter());

  return printer;
}

}  // namespace

std::string FormatProto(const google::protobuf::Message &message) {
  static const TextFormat::Printer *printer = CreateSgxProtoPrinter().release();

  std::string text;
  printer->PrintToString(message, &text);
  return text;
}

}  // namespace sgx
}  // namespace asylo
