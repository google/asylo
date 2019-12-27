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

#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/byte_container_reader.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "QuoteVerification/Src/AttestationLibrary/include/QuoteVerification/QuoteConstants.h"

namespace asylo {
namespace sgx {
namespace {

namespace constants = ::intel::sgx::qvl::constants;

template <typename ContainerT>
bool Contains(const ContainerT &container,
              const typename ContainerT::value_type &value) {
  return std::find(std::begin(container), std::end(container), value) !=
         std::end(container);
}

}  // namespace

StatusOr<IntelQeQuote> ParseDcapPackedQuote(ByteContainerView packed_quote) {
  ByteContainerReader reader(packed_quote);
  IntelQeQuote quote;
  ASYLO_RETURN_IF_ERROR(reader.ReadSingle(&quote.header));
  ASYLO_RETURN_IF_ERROR(reader.ReadSingle(&quote.body));

  if (!Contains(constants::ALLOWED_ATTESTATION_KEY_TYPES,
                quote.header.algorithm)) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrCat("Invalid signature algorithm: ", quote.header.algorithm));
  }

  // |signature_size| is called "Quote Signature Data Len" in the Intel SGX
  // ECDSA QuoteGenReference API doc. It's the length of the "Quote Signature
  // Data", which makes up the rest of the data in the quote.
  uint32_t signature_size = 0;
  ASYLO_RETURN_IF_ERROR(reader.ReadSingle(&signature_size));
  if (signature_size != reader.BytesRemaining()) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
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
  if (!Contains(constants::SUPPORTED_PCK_IDS,
                quote.cert_data.qe_cert_data_type)) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  absl::StrFormat("Invalid cert data type: %d",
                                  quote.cert_data.qe_cert_data_type));
  }

  uint32_t cert_data_size = 0;
  ASYLO_RETURN_IF_ERROR(reader.ReadSingle(&cert_data_size));
  quote.cert_data.qe_cert_data.reserve(cert_data_size);
  ASYLO_RETURN_IF_ERROR(
      reader.ReadMultiple(cert_data_size, &quote.cert_data.qe_cert_data));

  if (reader.BytesRemaining() != 0) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrFormat("Expected no bytes left, but %d bytes are remaining",
                        reader.BytesRemaining()));
  }

  return quote;
}

}  // namespace sgx
}  // namespace asylo
