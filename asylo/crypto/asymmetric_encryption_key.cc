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

#include "asylo/crypto/asymmetric_encryption_key.h"

#include <memory>

#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

StatusOr<AsymmetricEncryptionKeyProto> ConvertToAsymmetricEncryptionKeyProto(
    const AsymmetricEncryptionKey &key) {
  AsymmetricEncryptionKeyProto asymmetric_encryption_key;
  asymmetric_encryption_key.set_key_type(
      AsymmetricEncryptionKeyProto::ENCRYPTION_KEY);
  asymmetric_encryption_key.set_encoding(
      AsymmetricKeyEncoding::ASYMMETRIC_KEY_DER);
  asymmetric_encryption_key.set_encryption_scheme(key.GetEncryptionScheme());

  std::string serialized_encryption_key_der;
  ASYLO_ASSIGN_OR_RETURN(serialized_encryption_key_der, key.SerializeToDer());
  asymmetric_encryption_key.set_key(serialized_encryption_key_der);

  return asymmetric_encryption_key;
}

StatusOr<AsymmetricEncryptionKeyProto> ConvertToAsymmetricEncryptionKeyProto(
    const AsymmetricDecryptionKey &key) {
  std::unique_ptr<AsymmetricEncryptionKey> encryption_key;
  ASYLO_ASSIGN_OR_RETURN(encryption_key, key.GetEncryptionKey());
  return ConvertToAsymmetricEncryptionKeyProto(*encryption_key);
}

}  // namespace asylo
