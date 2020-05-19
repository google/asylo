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

#include "asylo/test/grpc/client_side_auth_test_constants.h"

#include <cstdint>
#include <utility>

#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/util/proto_parse_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "debug_key_mrsigner.h"

namespace asylo {

const uint32_t kClientSideAuthServerIsvprodid = 1;
const uint32_t kClientSideAuthServerIsvsvn = 2;

StatusOr<SgxIdentityExpectation> ClientSideAuthEnclaveSgxIdentityExpectation() {
  SgxIdentity sgx_identity;
  sgx::CodeIdentity *code_identity = sgx_identity.mutable_code_identity();
  code_identity->set_miscselect(0);
  sgx::SecsAttributeSet attributes;
  ASYLO_ASSIGN_OR_RETURN(attributes,
                         sgx::SecsAttributeSet::FromBits(
                             {sgx::AttributeBit::INIT, sgx::AttributeBit::DEBUG,
                              sgx::AttributeBit::MODE64BIT}));
  *code_identity->mutable_attributes() = attributes.ToProtoAttributes();

  sgx::SignerAssignedIdentity *signer_assigned_identity =
      code_identity->mutable_signer_assigned_identity();
  *signer_assigned_identity->mutable_mrsigner() =
      ParseTextProtoOrDie(linux_sgx::kDebugKeyMrsignerTextProto);
  signer_assigned_identity->set_isvprodid(kClientSideAuthServerIsvprodid);
  signer_assigned_identity->set_isvsvn(kClientSideAuthServerIsvsvn);

  return asylo::CreateSgxIdentityExpectation(
      std::move(sgx_identity), SgxIdentityMatchSpecOptions::DEFAULT);
}

}  // namespace asylo
