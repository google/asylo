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

#ifndef ASYLO_CRYPTO_FAKE_SIGNING_KEY_H_
#define ASYLO_CRYPTO_FAKE_SIGNING_KEY_H_

#include <openssl/base.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// A fake verifying key.
class FakeVerifyingKey : public VerifyingKey {
 public:
  // Creates a FakeVerifyingKey with underlying key data |scheme| and
  // |serialize_to_der_result|.
  FakeVerifyingKey(SignatureScheme scheme,
                   StatusOr<std::string> serialize_to_der_result);

  // From VerifyingKey.

  // Returns true if and only if |other| is a FakeVerifyingKey and
  // |other| has the same SerializeToDer() and signature scheme as this object.
  bool operator==(const VerifyingKey &other) const override;

  // Returns the signature scheme set at construction.
  SignatureScheme GetSignatureScheme() const override;

  // Returns the DER-encoded key value or the non-OK Status value passed at
  // construction.
  StatusOr<std::string> SerializeToDer() const override;

  // Unimplemented. Because of this, SerializeToKeyProto is also unimplemented
  // for PEM.
  StatusOr<std::string> SerializeToPem() const override;

  // Verifies that the signature is |message| appended to the value of
  // SerializeToDer(). If SerializeToDer() returns a non-OK Status, return that
  // status.
  Status Verify(ByteContainerView message,
                ByteContainerView signature) const override;

  // Unimplemented.
  Status Verify(ByteContainerView message,
                const Signature &signature) const override;

 private:
  const SignatureScheme scheme_;
  const StatusOr<std::string> serialize_to_der_result_;
};

// A fake signing key.
class FakeSigningKey : public SigningKey {
 public:
  // Creates a FakeSigningKey with underlying key data |scheme| and
  // |serialize_to_der_result|.
  explicit FakeSigningKey(SignatureScheme scheme,
                          StatusOr<std::string> serialize_to_der_result);

  // From SigningKey.

  // Returns the signature scheme set at construction.
  SignatureScheme GetSignatureScheme() const override;

  // Returns the DER-encoded key value or the non-OK Status value passed at
  // construction.
  StatusOr<CleansingVector<uint8_t>> SerializeToDer() const override;

  // Unimplemented. Because of this, SerializeToKeyProto is also unimplemented
  // for PEM.
  StatusOr<CleansingVector<char>> SerializeToPem() const override;

  // Creates and returns the verifying key counterpart to this object.
  StatusOr<std::unique_ptr<VerifyingKey>> GetVerifyingKey() const override;

  // Appends |message| to the value of SerializeToDer(), and returns the result
  // through |signature|. If SerializeToDer() returns a non-OK Status, returns
  // that status.
  Status Sign(ByteContainerView message,
              std::vector<uint8_t> *signature) const override;

  // Unimplemented.
  Status Sign(ByteContainerView message, Signature *signature) const override;

  // From X509Signer.

  // Unimplemented.
  StatusOr<std::string> SerializePublicKeyToDer() const override;

  // Unimplemented.
  Status SignX509(X509 *x509) const override;

  // Unimplemented.
  Status SignX509Req(X509_REQ *x509_req) const override;

 private:
  const SignatureScheme scheme_;
  const StatusOr<std::string> serialize_to_der_result_;
};

}  // namespace asylo

#endif  // ASYLO_CRYPTO_FAKE_SIGNING_KEY_H_
