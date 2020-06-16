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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_PPID_EK_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_PPID_EK_H_

#include "absl/strings/string_view.h"
#include "asylo/crypto/keys.pb.h"

namespace asylo {
namespace sgx {

// Fixed, Intel-defined encryption key to be used to send PPIDs to the PCS.
// This key is NOT a secret, as it's well-known and advertised by Intel to the
// public.
extern const absl::string_view kPpidEkTextProto;

// Returns the PPID EK as a protobuf message.
AsymmetricEncryptionKeyProto GetPpidEkProto();

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_PPID_EK_H_
