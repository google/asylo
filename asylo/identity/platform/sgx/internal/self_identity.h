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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SELF_IDENTITY_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SELF_IDENTITY_H_

#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"

namespace asylo {
namespace sgx {

struct SelfIdentity {
  SelfIdentity();
  ~SelfIdentity() = default;

  // Raw fields from the hardware report.
  UnsafeBytes<kCpusvnSize> cpusvn;
  uint32_t miscselect;
  SecsAttributeSet attributes;
  UnsafeBytes<kSha256DigestLength> mrenclave;
  UnsafeBytes<kSha256DigestLength> mrsigner;
  uint16_t isvprodid;
  uint16_t isvsvn;

  // Protobuf represenation of the enclave identity.
  SgxIdentity sgx_identity;
};

// Returns a pointer to a SelfIdentity object that holds identity of the current
// enclave. The ownership of the object remains with the callee.
const SelfIdentity *GetSelfIdentity();

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SELF_IDENTITY_H_
