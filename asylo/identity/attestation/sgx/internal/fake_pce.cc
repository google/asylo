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

#include "asylo/identity/attestation/sgx/internal/fake_pce.h"

#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/sgx_identity_util.h"
#include "asylo/identity/sgx/sgx_identity_util_internal.h"

namespace asylo {
namespace sgx {

FakePce::FakePce(std::unique_ptr<SigningKey> pck, uint16_t pce_svn)
    : pck_(std::move(pck)), pce_svn_(pce_svn) {}

StatusOr<std::unique_ptr<FakePce>> FakePce::CreateFromFakePki(
    uint16_t pce_svn) {
  std::unique_ptr<EcdsaP256Sha256SigningKey> pck;
  ASYLO_ASSIGN_OR_RETURN(pck,
                         EcdsaP256Sha256SigningKey::CreateFromPem(kFakePckPem));
  return absl::make_unique<FakePce>(std::move(pck), pce_svn);
}

Status FakePce::SetEnclaveDir(const std::string &path) {
  return Status::OkStatus();
}

Status FakePce::GetPceTargetinfo(Targetinfo *targetinfo, uint16_t *pce_svn) {
  // Use a well-formed Targetinfo (all reserved fields are cleared and all
  // required bits are set).
  SetTargetinfoFromSelfIdentity(targetinfo);
  targetinfo->attributes = SecsAttributeSet::GetMustBeSetBits();
  targetinfo->miscselect = 0;

  *pce_svn = pce_svn_;

  return Status::OkStatus();
}

Status FakePce::PceSignReport(const Report &report, uint16_t /*target_pce_svn*/,
                              UnsafeBytes<kCpusvnSize> /*target_cpu_svn*/,
                              std::string *signature) {
  std::string report_bin = ConvertTrivialObjectToBinaryString(report);
  Signature pck_signature;
  ASYLO_RETURN_IF_ERROR(pck_->Sign(report_bin, &pck_signature));

  const EcdsaSignature &ecdsa_signature = pck_signature.ecdsa_signature();
  *signature = absl::StrCat(ecdsa_signature.r(), ecdsa_signature.s());

  return Status::OkStatus();
}

Status FakePce::GetPceInfo(const Report &report,
                           absl::Span<const uint8_t> ppid_encryption_key,
                           AsymmetricEncryptionScheme ppid_encryption_scheme,
                           std::string *ppid_encrypted, uint16_t *pce_svn,
                           uint16_t *pce_id,
                           SignatureScheme *signature_scheme) {
  return Status(error::GoogleError::UNIMPLEMENTED, "Not implemented");
}

StatusOr<Targetinfo> FakePce::GetQeTargetinfo() {
  return Status(error::GoogleError::UNIMPLEMENTED, "Not implemented");
}

StatusOr<std::vector<uint8_t>> FakePce::GetQeQuote(const Report &report) {
  return Status(error::GoogleError::UNIMPLEMENTED, "Not implemented");
}

}  // namespace sgx
}  // namespace asylo
