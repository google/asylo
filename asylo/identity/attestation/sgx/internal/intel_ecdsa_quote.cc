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

#include "asylo/identity/attestation/sgx/internal/intel_ecdsa_quote.h"

#include <algorithm>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/byte_container_reader.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity.pb.h"

namespace asylo {
namespace sgx {

StatusOr<IntelQeQuote> ParseDcapPackedQuote(ByteContainerView packed_quote) {
  ByteContainerReader reader(packed_quote);
  IntelQeQuote quote;
  ASYLO_RETURN_IF_ERROR(reader.ReadSingle(&quote.header));
  ASYLO_RETURN_IF_ERROR(reader.ReadSingle(&quote.body));

  // |signature_size| is called "Quote Signature Data Len" in the Intel SGX
  // ECDSA QuoteGenReference API doc. It's the length of the "Quote Signature
  // Data", which makes up the rest of the data in the quote.
  uint32_t signature_size = 0;
  ASYLO_RETURN_IF_ERROR(reader.ReadSingle(&signature_size));
  if (signature_size != reader.BytesRemaining()) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrFormat(
                      "Expected signature data size of %d, actual value was %d",
                      reader.BytesRemaining(), signature_size));
  }

  ASYLO_RETURN_IF_ERROR(reader.ReadSingle(&quote.signature));

  uint16_t authn_data_size = 0;
  ASYLO_RETURN_IF_ERROR(reader.ReadSingle(&authn_data_size));
  quote.qe_authn_data.reserve(authn_data_size);
  ASYLO_RETURN_IF_ERROR(
      reader.ReadMultiple(authn_data_size, &quote.qe_authn_data));
  ASYLO_RETURN_IF_ERROR(reader.ReadSingle(&quote.cert_data.qe_cert_data_type));

  uint32_t cert_data_size = 0;
  ASYLO_RETURN_IF_ERROR(reader.ReadSingle(&cert_data_size));
  quote.cert_data.qe_cert_data.reserve(cert_data_size);
  ASYLO_RETURN_IF_ERROR(
      reader.ReadMultiple(cert_data_size, &quote.cert_data.qe_cert_data));

  if (reader.BytesRemaining() != 0) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Expected no bytes left, but %d bytes are remaining",
                        reader.BytesRemaining()));
  }

  return quote;
}

std::vector<uint8_t> PackDcapQuote(const IntelQeQuote &quote) {
  const uint16_t kSizeOfQeAuthData = quote.qe_authn_data.size();
  const uint32_t kSizeOfQeCertData = quote.cert_data.qe_cert_data.size();
  const uint32_t kSizeOfSignatureData =
      sizeof(quote.signature) + sizeof(kSizeOfQeAuthData) + kSizeOfQeAuthData +
      sizeof(quote.cert_data.qe_cert_data_type) + sizeof(kSizeOfQeCertData) +
      kSizeOfQeCertData;

  std::vector<uint8_t> output;
  AppendTrivialObject(quote.header, &output);
  AppendTrivialObject(quote.body, &output);
  AppendTrivialObject(kSizeOfSignatureData, &output);
  AppendTrivialObject(quote.signature, &output);
  AppendTrivialObject(kSizeOfQeAuthData, &output);
  std::copy(quote.qe_authn_data.begin(), quote.qe_authn_data.end(),
            std::back_inserter(output));
  AppendTrivialObject(quote.cert_data.qe_cert_data_type, &output);
  AppendTrivialObject(kSizeOfQeCertData, &output);
  std::copy(quote.cert_data.qe_cert_data.begin(),
            quote.cert_data.qe_cert_data.end(), std::back_inserter(output));

  return output;
}

StatusOr<Assertion> PackedQuoteToAssertion(ByteContainerView packed_quote) {
  ASYLO_RETURN_IF_ERROR(ParseDcapPackedQuote(packed_quote));

  Assertion assertion;
  SetSgxIntelEcdsaQeRemoteAssertionDescription(assertion.mutable_description());
  assertion.set_assertion(packed_quote.data(), packed_quote.size());

  return assertion;
}

StatusOr<std::vector<uint8_t>> AssertionToPackedQuote(
    const Assertion &assertion) {
  if (assertion.description().identity_type() != CODE_IDENTITY) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Assertion contained invalid identity type: ",
                               assertion.description().identity_type()));
  }

  if (assertion.description().authority_type() !=
      kSgxIntelEcdsaQeRemoteAssertionAuthority) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Assertion contained invalid authority type: ",
                               assertion.description().authority_type()));
  }

  ASYLO_RETURN_IF_ERROR(ParseDcapPackedQuote(assertion.assertion()));

  return std::vector<uint8_t>{assertion.assertion().begin(),
                              assertion.assertion().end()};
}

}  // namespace sgx
}  // namespace asylo
