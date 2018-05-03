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

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/aes_gcm_siv.h"
#include "quickstart/solution/demo.pb.h"
#include "asylo/trusted_application.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/statusor.h"

#ifndef arraysize
#define arraysize(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

namespace asylo {
namespace {

// Set to accept absurdly large user input.
constexpr size_t kMaxMessageSize = 1 << 16;

// Dummy 128-bit AES key.
constexpr uint8_t kAesKey128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                  0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
                                  0x12, 0x13, 0x14, 0x15};

// Note that the following functions are implemented with cleansing types, which
// ensure that their variables' contents are wiped when they go out of scope.
// However, as secret data is coming from user input, such protections are
// somewhat overkill, and are mainly in place for type compatibility with
// `AesGcmSivCryptor`.

// Encrypts a message against `kAesKey128` and returns a 12-byte nonce followed
// by authenticated ciphertext, encoded as a hex string. `message` must be less
// than or equal to `kMaxMessageSize` in length.
const StatusOr<std::string> EncryptMessage(const std::string &message) {
  AesGcmSivCryptor cryptor(kMaxMessageSize, new AesGcmSivNonceGenerator());

  CleansingVector<uint8_t> key(kAesKey128, kAesKey128 + arraysize(kAesKey128));
  CleansingString additional_authenticated_data;
  CleansingString nonce;
  CleansingString ciphertext;

  Status status = cryptor.Seal(key, additional_authenticated_data, message,
                               &nonce, &ciphertext);
  if (!status.ok()) {
    return status;
  }

  return absl::BytesToHexString(absl::StrCat(nonce, ciphertext));
}

// Decrypts a message using `kAesKey128`. Expects `nonce_and_ciphertext` to be
// encoded as a hex string, and lead with a 12-byte nonce. Intended to be
// used by the reader for completing the exercise.
const StatusOr<std::string> DecryptMessage(const std::string &nonce_and_ciphertext) {
  std::string decoded_input = absl::HexStringToBytes(nonce_and_ciphertext);
  CleansingString clean_input(decoded_input.data(), decoded_input.size());

  if (clean_input.size() < kAesGcmSivNonceSize) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        absl::StrCat("Input too short: expected at least ", kAesGcmSivNonceSize,
                     " bytes, got ", clean_input.size()));
  }

  CleansingString additional_authenticated_data;
  CleansingString nonce = clean_input.substr(0, kAesGcmSivNonceSize);
  CleansingString ciphertext = clean_input.substr(kAesGcmSivNonceSize);
  CleansingString plaintext;

  CleansingVector<uint8_t> key(kAesKey128, kAesKey128 + arraysize(kAesKey128));

  AesGcmSivCryptor cryptor(kMaxMessageSize, new AesGcmSivNonceGenerator());
  Status status = cryptor.Open(key, additional_authenticated_data, ciphertext,
                               nonce, &plaintext);
  if (!status.ok()) {
    return status;
  }

  return std::string(plaintext.data(), plaintext.size());
}

}  // namespace

class EnclaveDemo : public TrustedApplication {
 public:
  EnclaveDemo() = default;

  Status Run(const EnclaveInput &input, EnclaveOutput *output) {
    std::string user_message = GetEnclaveUserMessage(input);

    StatusOr<std::string> result;
    switch (GetEnclaveUserAction(input)) {
      case guide::asylo::Demo::ENCRYPT:
        result = EncryptMessage(user_message);
        break;
      case guide::asylo::Demo::DECRYPT:
        result = DecryptMessage(user_message);
        break;
      default:
        result =
            Status(error::GoogleError::INVALID_ARGUMENT, "Action unspecified");
    }
    if (!result.ok()) {
      return result.status();
    }

    SetEnclaveOutputMessage(output, result.ValueOrDie());

    return Status::OkStatus();
  }

  // Retrieves user message from |input|.
  const std::string GetEnclaveUserMessage(const EnclaveInput &input) {
    return input.GetExtension(guide::asylo::quickstart_input).value();
  }

  // Retrieves user action from |input|.
  guide::asylo::Demo::Action GetEnclaveUserAction(
      const EnclaveInput &input) {
    return input.GetExtension(guide::asylo::quickstart_input).action();
  }

  // Populates |enclave_output|->value() with |output_message|. Intended to be
  // used by the reader for completing the exercise.
  void SetEnclaveOutputMessage(EnclaveOutput *enclave_output,
                               const std::string &output_message) {
    guide::asylo::Demo *output =
        enclave_output->MutableExtension(guide::asylo::quickstart_output);
    output->set_value(output_message);
  }
};

TrustedApplication *BuildTrustedApplication() { return new EnclaveDemo; }

}  // namespace asylo
