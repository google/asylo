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
#include "asylo/crypto/signing_key.h"

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

bool VerifyingKey::operator!=(const VerifyingKey &other) const {
  return !(*this == other);
}

StatusOr<AsymmetricSigningKeyProto> VerifyingKey::SerializeToKeyProto(
    AsymmetricKeyEncoding encoding) const {
  AsymmetricSigningKeyProto key_proto;
  key_proto.set_key_type(AsymmetricSigningKeyProto::VERIFYING_KEY);
  key_proto.set_signature_scheme(GetSignatureScheme());
  key_proto.set_encoding(encoding);

  switch (encoding) {
    case ASYMMETRIC_KEY_DER:
      ASYLO_ASSIGN_OR_RETURN(*key_proto.mutable_key(), SerializeToDer());
      break;
    case ASYMMETRIC_KEY_PEM:
      ASYLO_ASSIGN_OR_RETURN(*key_proto.mutable_key(), SerializeToPem());
      break;
    case UNKNOWN_ASYMMETRIC_KEY_ENCODING:
      return Status(absl::StatusCode::kInvalidArgument,
                    absl::StrFormat("Encoding (%s) is unsupported",
                                    ProtoEnumValueName(encoding)));
  }

  return key_proto;
}

StatusOr<AsymmetricSigningKeyProto> SigningKey::SerializeToKeyProto(
    AsymmetricKeyEncoding encoding) const {
  AsymmetricSigningKeyProto key_proto;
  key_proto.set_key_type(AsymmetricSigningKeyProto::SIGNING_KEY);
  key_proto.set_signature_scheme(GetSignatureScheme());
  key_proto.set_encoding(encoding);

  switch (encoding) {
    case ASYMMETRIC_KEY_DER: {
      CleansingVector<uint8_t> serialized;
      ASYLO_ASSIGN_OR_RETURN(serialized, SerializeToDer());
      *key_proto.mutable_key() = CopyToByteContainer<std::string>(serialized);
      break;
    }
    case ASYMMETRIC_KEY_PEM: {
      CleansingVector<char> serialized;
      ASYLO_ASSIGN_OR_RETURN(serialized, SerializeToPem());
      *key_proto.mutable_key() = CopyToByteContainer<std::string>(serialized);
      break;
    }
    case UNKNOWN_ASYMMETRIC_KEY_ENCODING:
      return Status(absl::StatusCode::kInvalidArgument,
                    absl::StrFormat("Encoding (%s) is unsupported",
                                    ProtoEnumValueName(encoding)));
  }

  return key_proto;
}

}  // namespace asylo
