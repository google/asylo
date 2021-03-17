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
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/rsa_oaep_encryption_key.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/attestation/sgx/internal/pce_util.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/provisioning/sgx/internal/fake_sgx_pki.h"

namespace asylo {
namespace sgx {

constexpr uint16_t FakePce::kPceSvn;
constexpr uint16_t FakePce::kPceId;

const UnsafeBytes<kPpidSize> FakePce::kPpid =
    UnsafeBytes<kPpidSize>("123456abcdef1234");

FakePce::FakePce(std::unique_ptr<SigningKey> pck, uint16_t pce_svn,
                 uint16_t pce_id, UnsafeBytes<kPpidSize> ppid)
    : pck_(std::move(pck)), pce_svn_(pce_svn), pce_id_(pce_id), ppid_(ppid) {}

StatusOr<std::unique_ptr<FakePce>> FakePce::CreateFromFakePki() {
  std::unique_ptr<EcdsaP256Sha256SigningKey> pck;
  ASYLO_ASSIGN_OR_RETURN(pck, EcdsaP256Sha256SigningKey::CreateFromPem(
                                  kFakeSgxPck.signing_key_pem));
  return absl::make_unique<FakePce>(std::move(pck), kPceSvn, kPceId, kPpid);
}

Status FakePce::SetPckCertificateChain(const CertificateChain &chain) {
  return absl::OkStatus();
}

Status FakePce::SetEnclaveDir(const std::string &path) {
  return absl::OkStatus();
}

Status FakePce::GetPceTargetinfo(Targetinfo *targetinfo, uint16_t *pce_svn) {
  // Use a well-formed Targetinfo (all reserved fields are cleared and all
  // required bits are set).
  SetTargetinfoFromSelfIdentity(targetinfo);
  targetinfo->attributes = SecsAttributeSet::GetMustBeSetBits();
  targetinfo->miscselect = 0;

  *pce_svn = pce_svn_;

  return absl::OkStatus();
}

Status FakePce::PceSignReport(const Report &report, uint16_t /*target_pce_svn*/,
                              UnsafeBytes<kCpusvnSize> /*target_cpu_svn*/,
                              std::string *signature) {
  Signature pck_signature;
  ASYLO_RETURN_IF_ERROR(pck_->Sign(
      ByteContainerView(&report.body, sizeof(report.body)), &pck_signature));

  const EcdsaSignature &ecdsa_signature = pck_signature.ecdsa_signature();
  *signature = absl::StrCat(ecdsa_signature.r(), ecdsa_signature.s());

  return absl::OkStatus();
}

Status FakePce::GetPceInfo(const Report &report,
                           absl::Span<const uint8_t> ppid_encryption_key,
                           AsymmetricEncryptionScheme ppid_encryption_scheme,
                           std::string *ppid_encrypted, uint16_t *pce_svn,
                           uint16_t *pce_id,
                           SignatureScheme *signature_scheme) {
  if (ppid_encryption_scheme != RSA3072_OAEP) {
    return absl::InvalidArgumentError("Unsupported PPID encryption scheme");
  }

  bssl::UniquePtr<RSA> ppidek_rsa;
  ASYLO_ASSIGN_OR_RETURN(ppidek_rsa,
                         ParseRsa3072PublicKey(ppid_encryption_key));

  std::unique_ptr<RsaOaepEncryptionKey> ppidek;
  ASYLO_ASSIGN_OR_RETURN(
      ppidek, RsaOaepEncryptionKey::Create(std::move(ppidek_rsa), SHA256));

  std::vector<uint8_t> encrypted_ppid;
  ASYLO_RETURN_IF_ERROR(ppidek->Encrypt(ppid_, &encrypted_ppid));

  *ppid_encrypted = CopyToByteContainer<std::string>(encrypted_ppid);

  *pce_svn = pce_svn_;
  *pce_id = pce_id_;
  *signature_scheme = pck_->GetSignatureScheme();

  return absl::OkStatus();
}

StatusOr<Targetinfo> FakePce::GetQeTargetinfo() {
  return Status(absl::StatusCode::kUnimplemented, "Not implemented");
}

StatusOr<std::vector<uint8_t>> FakePce::GetQeQuote(const Report &report) {
  return Status(absl::StatusCode::kUnimplemented, "Not implemented");
}

}  // namespace sgx
}  // namespace asylo
