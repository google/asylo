/*
 *
 * Copyright 2017 Asylo authors
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

#include "asylo/identity/sealing/secret_sealer.h"

#include <cstdint>
#include <string>
#include <vector>

#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {

Status SecretSealer::Reseal(const SealedSecret &old_sealed_secret,
                            const SealedSecretHeader &new_header,
                            SealedSecret *new_sealed_secret) {
  CleansingVector<uint8_t> unsealed_secret;
  ASYLO_RETURN_IF_ERROR(Unseal(old_sealed_secret, &unsealed_secret));
  return Seal(new_header, old_sealed_secret.additional_authenticated_data(),
              unsealed_secret, new_sealed_secret);
}

StatusOr<std::string> SecretSealer::GenerateSealerId(SealingRootType type,
                                                     const std::string &name) {
  std::string serialized;
  ASYLO_RETURN_IF_ERROR(
      SerializeByteContainers(&serialized, SealingRootType_Name(type), name));
  return serialized;
}

}  // namespace asylo
