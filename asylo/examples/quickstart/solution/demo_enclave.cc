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

#include <string>

#include "absl/base/macros.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/aead_cryptor.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/examples/quickstart/solution/demo.pb.h"
#include "asylo/trusted_application.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

// Example 128-bit AES key.
constexpr uint8_t kAesKey128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                  0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
                                  0x12, 0x13, 0x14, 0x15};

// Helper function that adapts absl::BytesToHexString, allowing it to be used
// with ByteContainerView.
std::string BytesToHexString(ByteContainerView bytes) {
  return absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char *>(bytes.data()), bytes.size()));
}

// Encrypts a message against `kAesKey128` and returns a 12-byte nonce followed
// by authenticated ciphertext, encoded as a hex string.
const StatusOr<std::string> EncryptMessage(const std::string &message) {
  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSIGN_OR_RETURN(cryptor,
                         AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));

  std::vector<uint8_t> additional_authenticated_data;
  std::vector<uint8_t> nonce(cryptor->NonceSize());
  std::vector<uint8_t> ciphertext(message.size() + cryptor->MaxSealOverhead());
  size_t ciphertext_size;

  ASYLO_RETURN_IF_ERROR(cryptor->Seal(
      message, additional_authenticated_data, absl::MakeSpan(nonce),
      absl::MakeSpan(ciphertext), &ciphertext_size));

  return absl::StrCat(BytesToHexString(nonce), BytesToHexString(ciphertext));
}

// Decrypts a message using `kAesKey128`. Expects `nonce_and_ciphertext` to be
// encoded as a hex string, and lead with a 12-byte nonce. Intended to be
// used by the reader for completing the exercise.
const StatusOr<CleansingString> DecryptMessage(
    const std::string &nonce_and_ciphertext) {
  std::string input_bytes = absl::HexStringToBytes(nonce_and_ciphertext);

  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSIGN_OR_RETURN(cryptor,
                         AeadCryptor::CreateAesGcmSivCryptor(kAesKey128));

  if (input_bytes.size() < cryptor->NonceSize()) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Input too short: expected at least ",
                     cryptor->NonceSize(), " bytes, got ", input_bytes.size()));
  }

  std::vector<uint8_t> additional_authenticated_data;
  std::vector<uint8_t> nonce = {input_bytes.begin(),
                                input_bytes.begin() + cryptor->NonceSize()};
  std::vector<uint8_t> ciphertext = {input_bytes.begin() + cryptor->NonceSize(),
                                     input_bytes.end()};

  // The plaintext is always smaller than the ciphertext, so use
  // `ciphertext.size()` as an upper bound on the plaintext buffer size.
  CleansingVector<uint8_t> plaintext(ciphertext.size());
  size_t plaintext_size;

  ASYLO_RETURN_IF_ERROR(cryptor->Open(ciphertext, additional_authenticated_data,
                                      nonce, absl::MakeSpan(plaintext),
                                      &plaintext_size));

  return CleansingString(plaintext.begin(), plaintext.end());
}

}  // namespace

class EnclaveDemo : public TrustedApplication {
 public:
  EnclaveDemo() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    std::string user_message = GetEnclaveUserMessage(input);

    switch (GetEnclaveUserAction(input)) {
      case guide::asylo::Demo::ENCRYPT: {
        std::string result;
        ASYLO_ASSIGN_OR_RETURN(result, EncryptMessage(user_message));
        SetEnclaveOutputMessage(output, result);
        break;
      }
      case guide::asylo::Demo::DECRYPT: {
        CleansingString result;
        ASYLO_ASSIGN_OR_RETURN(result, DecryptMessage(user_message));
        SetEnclaveOutputMessage(output, result);
        break;
      }
      default:
        return absl::InvalidArgumentError("Action unspecified");
    }

    return absl::OkStatus();
  }

  // Retrieves user message from |input|.
  const std::string GetEnclaveUserMessage(const EnclaveInput &input) {
    return input.GetExtension(guide::asylo::quickstart_input).value();
  }

  // Retrieves user action from |input|.
  guide::asylo::Demo::Action GetEnclaveUserAction(const EnclaveInput &input) {
    return input.GetExtension(guide::asylo::quickstart_input).action();
  }

  // Populates |enclave_output|->value() with |output_message|. Intended to be
  // used by the reader for completing the exercise.
  void SetEnclaveOutputMessage(EnclaveOutput *enclave_output,
                               absl::string_view output_message) {
    guide::asylo::Demo *output =
        enclave_output->MutableExtension(guide::asylo::quickstart_output);
    output->set_value(std::string(output_message));
  }
};

TrustedApplication *BuildTrustedApplication() { return new EnclaveDemo; }

}  // namespace asylo
