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
#include <iterator>
#include <type_traits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/test/util/memory_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "QuoteVerification/Src/AttestationLibrary/include/QuoteVerification/QuoteConstants.h"

namespace asylo {
namespace sgx {
namespace {

namespace constants = ::intel::sgx::qvl::constants;

using ::testing::ContainerEq;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Test;

class IntelEcdsaQuoteTest : public Test {
 protected:
  // The Intel DCAP api returns a contiguously-allocated quote buffer. This
  // helper function will pack up a valid quote into such a buffer.
  std::vector<uint8_t> PackQuote(const IntelQeQuote &quote) {
    const uint16_t kSizeOfQeAuthData = quote.qe_authn_data.size();
    const uint32_t kSizeOfQeCertData = quote.cert_data.qe_cert_data.size();
    const uint32_t kSizeOfSignatureData =
        sizeof(quote.signature) + sizeof(kSizeOfQeAuthData) +
        kSizeOfQeAuthData + sizeof(quote.cert_data.qe_cert_data_type) +
        sizeof(kSizeOfQeCertData) + kSizeOfQeCertData;

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

  IntelQeQuote CreateRandomParsableQuote() {
    IntelQeQuote quote;

    RandomFillTrivialObject(&quote.header);
    RandomFillTrivialObject(&quote.body);
    RandomFillTrivialObject(&quote.signature);
    AppendTrivialObject(TrivialRandomObject<UnsafeBytes<123>>(),
                        &quote.qe_authn_data);
    AppendTrivialObject(TrivialRandomObject<UnsafeBytes<456>>(),
                        &quote.cert_data.qe_cert_data);

    // These values must be fixed for a quote to be valid.
    quote.cert_data.qe_cert_data_type = constants::PCK_ID_PCK_CERT_CHAIN;
    quote.header.algorithm = constants::ECDSA_256_WITH_P256_CURVE;

    return quote;
  }

  void ExpectQuoteEquals(const StatusOr<IntelQeQuote> &actual_quote,
                         const IntelQeQuote &expected_quote) {
    ASYLO_ASSERT_OK(actual_quote);
    EXPECT_THAT(actual_quote.ValueOrDie().header,
                TrivialObjectEq(expected_quote.header));
    EXPECT_THAT(actual_quote.ValueOrDie().body,
                TrivialObjectEq(expected_quote.body));
    EXPECT_THAT(actual_quote.ValueOrDie().signature,
                TrivialObjectEq(expected_quote.signature));
    EXPECT_THAT(actual_quote.ValueOrDie().qe_authn_data,
                ContainerEq(expected_quote.qe_authn_data));
    EXPECT_THAT(actual_quote.ValueOrDie().cert_data.qe_cert_data_type,
                Eq(expected_quote.cert_data.qe_cert_data_type));
    EXPECT_THAT(actual_quote.ValueOrDie().cert_data.qe_cert_data,
                ContainerEq(expected_quote.cert_data.qe_cert_data));
  }
};

TEST_F(IntelEcdsaQuoteTest, ParseSuccess) {
  const IntelQeQuote kExpectedQuote = CreateRandomParsableQuote();
  ExpectQuoteEquals(ParseDcapPackedQuote(PackQuote(kExpectedQuote)),
                    kExpectedQuote);
}

TEST_F(IntelEcdsaQuoteTest, ParseQuoteSucceedsWithoutOptionalAuthnData) {
  IntelQeQuote expected_quote = CreateRandomParsableQuote();
  expected_quote.qe_authn_data.clear();
  ExpectQuoteEquals(ParseDcapPackedQuote(PackQuote(expected_quote)),
                    expected_quote);
}

TEST_F(IntelEcdsaQuoteTest, ParseQuoteFailsDueToInputBufferBeingTooLarge) {
  std::vector<uint8_t> packed_quote = PackQuote(CreateRandomParsableQuote());
  packed_quote.push_back('x');

  Status status = ParseDcapPackedQuote(packed_quote).status();
  EXPECT_THAT(status, StatusIs(error::GoogleError::INVALID_ARGUMENT));
  EXPECT_THAT(
      std::string(status.error_message().begin(), status.error_message().end()),
      HasSubstr("Expected signature data size of "));
}

TEST_F(IntelEcdsaQuoteTest, ParseQuoteFailsDueToInputBufferBeingTooSmall) {
  std::vector<uint8_t> packed_quote = PackQuote(CreateRandomParsableQuote());
  do {
    packed_quote.pop_back();
    EXPECT_THAT(ParseDcapPackedQuote(packed_quote),
                StatusIs(error::GoogleError::INVALID_ARGUMENT));
  } while (!packed_quote.empty());
}

TEST_F(IntelEcdsaQuoteTest, ParseQuoteSucceedsWithAllValidAlgorithms) {
  IntelQeQuote quote = CreateRandomParsableQuote();
  for (auto valid_value : constants::ALLOWED_ATTESTATION_KEY_TYPES) {
    quote.header.algorithm = valid_value;
    EXPECT_THAT(ParseDcapPackedQuote(PackQuote(quote)), IsOk());
  }
}

TEST_F(IntelEcdsaQuoteTest,
       ParseQuoteFailsDueToInvalidQuoteSignatureAlgorithm) {
  IntelQeQuote quote = CreateRandomParsableQuote();
  quote.header.algorithm = 54321;
  EXPECT_THAT(ParseDcapPackedQuote(PackQuote(quote)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT,
                       "Invalid signature algorithm: 54321"));
}

TEST_F(IntelEcdsaQuoteTest, ParseQuoteSucceedsWithAllValidCertDataTypes) {
  IntelQeQuote quote = CreateRandomParsableQuote();
  for (auto valid_value : constants::SUPPORTED_PCK_IDS) {
    quote.cert_data.qe_cert_data_type = valid_value;
    EXPECT_THAT(ParseDcapPackedQuote(PackQuote(quote)), IsOk());
  }
}

TEST_F(IntelEcdsaQuoteTest, ParseQuoteFailsDueToInvalidCertDataType) {
  IntelQeQuote quote = CreateRandomParsableQuote();
  quote.cert_data.qe_cert_data_type = 1234;
  EXPECT_THAT(ParseDcapPackedQuote(PackQuote(quote)),
              StatusIs(error::GoogleError::INVALID_ARGUMENT,
                       "Invalid cert data type: 1234"));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
