/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/identity/platform/sgx/internal/ppid_ek.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/util/proto_parse_util.h"

namespace asylo {
namespace sgx {

extern const absl::string_view kPpidEkTextProto =
    R"pb(
  key_type: ENCRYPTION_KEY
  encoding: ASYMMETRIC_KEY_PEM
  encryption_scheme: RSA3072_OAEP
  key: "-----BEGIN PUBLIC KEY-----\n"
       "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA05b5Q0MRABxpRJw7/e6P\n"
       "OM2Vza10CXyH8adlAkyHwVcwpcmmpMz5HWIYHgCmdCdYWcobHfUxDvLV4Xk3OZQ9\n"
       "PeJQkxLWA+UZOkjwrgw37uBXJ73sFxsPOYYGVCB0hDS+NPpxb6H1TJpSD8S8LXou\n"
       "F+Ndog7KOQeYqQUaNPuPYJw6HiYwC/PzSUDZ913L0b9XjeUtzphXNfGTwxkugFU3\n"
       "q41kCNrm3WS0YoONQ6rSe8Jjqpfe7QmS1ohWhs0IIwMnmnh89DYS9bHmHVSriGn/\n"
       "GE/ch+40pmixgWe2zgpwFLyz4Y12HHPeAKtBykBRU2MEw2MLymLaqpzlAbfAD34L\n"
       "sL7p+A2ztmT9zZUXnFeO7MSsizYBXkxtHiFJoB3eBDlrNGhE6gZ24I0fosAmBcyR\n"
       "vqMXyHVGhRA5FlCOAkOYMXBp2DRxgudIJs3BgtPrb+lY5wZ3EB/fSXYwp2hCsBbX\n"
       "2pJ11X8udUOsg7Afw5AZzqqU0C5abBNy56a1wEWB41MnAgMBAAE=\n"
       "-----END PUBLIC KEY-----\n"
    )pb";

AsymmetricEncryptionKeyProto GetPpidEkProto() {
  return asylo::ParseTextProto<asylo::AsymmetricEncryptionKeyProto>(
             kPpidEkTextProto)
      .value();
}

}  // namespace sgx
}  // namespace asylo
