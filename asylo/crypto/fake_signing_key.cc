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

#include "asylo/crypto/fake_signing_key.h"

#include <algorithm>
#include <iterator>

#include "absl/memory/memory.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {

FakeVerifyingKey::FakeVerifyingKey(
    SignatureScheme scheme, StatusOr<std::string> serialize_to_der_result)
    : scheme_(scheme), serialize_to_der_result_(serialize_to_der_result) {}

bool FakeVerifyingKey::operator==(const VerifyingKey &other) const {
  FakeVerifyingKey const *other_key =
      dynamic_cast<FakeVerifyingKey const *>(&other);

  if (other_key == nullptr) {
    return false;
  }

  if (other_key->serialize_to_der_result_.status() !=
      serialize_to_der_result_.status()) {
    return false;
  }

  if (serialize_to_der_result_.ok() &&
      other_key->serialize_to_der_result_.ValueOrDie() !=
          serialize_to_der_result_.ValueOrDie()) {
    return false;
  }

  return other_key->scheme_ == scheme_;
}

SignatureScheme FakeVerifyingKey::GetSignatureScheme() const { return scheme_; }

StatusOr<std::string> FakeVerifyingKey::SerializeToDer() const {
  return serialize_to_der_result_;
}

StatusOr<std::string> FakeVerifyingKey::SerializeToPem() const {
  return Status(error::GoogleError::UNIMPLEMENTED,
                "SerializeToPem unimplemented");
}

Status FakeVerifyingKey::Verify(ByteContainerView message,
                                ByteContainerView signature) const {
  ASYLO_RETURN_IF_ERROR(serialize_to_der_result_.status());
  const std::string &key_der = serialize_to_der_result_.ValueOrDie();

  if (signature.size() != key_der.size() + message.size()) {
    return Status(error::GoogleError::UNAUTHENTICATED,
                  "Signature does not match the expected value");
  }

  if (!std::equal(key_der.cbegin(), key_der.cend(), signature.cbegin())) {
    return Status(error::GoogleError::UNAUTHENTICATED,
                  "Signature does not match the expected value");
  }

  if (!std::equal(message.cbegin(), message.cend(),
                  signature.cbegin() + key_der.size())) {
    return Status(error::GoogleError::UNAUTHENTICATED,
                  "Signature does not match the expected value");
  }

  return Status::OkStatus();
}

Status FakeVerifyingKey::Verify(ByteContainerView message,
                                const Signature &signature) const {
  return Status(error::GoogleError::UNIMPLEMENTED,
                "Verify overload unimplemented");
}

FakeSigningKey::FakeSigningKey(SignatureScheme scheme,
                               StatusOr<std::string> serialize_to_der_result)
    : scheme_(scheme), serialize_to_der_result_(serialize_to_der_result) {}

SignatureScheme FakeSigningKey::GetSignatureScheme() const { return scheme_; }

StatusOr<CleansingVector<uint8_t>> FakeSigningKey::SerializeToDer() const {
  ASYLO_RETURN_IF_ERROR(serialize_to_der_result_.status());
  return CopyToByteContainer<CleansingVector<uint8_t>>(
      serialize_to_der_result_.ValueOrDie());
}

StatusOr<CleansingVector<char>> FakeSigningKey::SerializeToPem() const {
  return Status(error::GoogleError::UNIMPLEMENTED,
                "SerializeToPem unimplemented");
}

StatusOr<std::unique_ptr<VerifyingKey>> FakeSigningKey::GetVerifyingKey()
    const {
  return absl::make_unique<FakeVerifyingKey>(scheme_, serialize_to_der_result_);
}

Status FakeSigningKey::Sign(ByteContainerView message,
                            std::vector<uint8_t> *signature) const {
  ASYLO_RETURN_IF_ERROR(serialize_to_der_result_.status());
  const std::string &key_der = serialize_to_der_result_.ValueOrDie();

  signature->clear();
  std::copy(key_der.cbegin(), key_der.cend(), std::back_inserter(*signature));
  std::copy(message.cbegin(), message.cend(), std::back_inserter(*signature));
  return Status::OkStatus();
}

Status FakeSigningKey::Sign(ByteContainerView message,
                            Signature *signature) const {
  return Status(error::GoogleError::UNIMPLEMENTED,
                "Sign overload unimplemented");
}

Status FakeSigningKey::SignX509(X509 *x509) const {
  return Status(error::GoogleError::UNIMPLEMENTED,
                "SignX509 overload unimplemented");
}

}  // namespace asylo
