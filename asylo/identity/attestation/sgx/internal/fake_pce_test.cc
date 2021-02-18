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
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/status/status.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/asymmetric_encryption_key.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/rsa_oaep_encryption_key.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/attestation/sgx/internal/pce_util.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/test/util/memory_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/cleansing_types.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;

TEST(FakePceTest, SetEnclaveDirSucceess) {
  std::unique_ptr<FakePce> fake_pce;
  ASYLO_ASSERT_OK_AND_ASSIGN(fake_pce, FakePce::CreateFromFakePki());

  ASYLO_EXPECT_OK(fake_pce->SetEnclaveDir("/foo/bar"));
}

TEST(FakePceTest, GetPceTargetinfoSuccess) {
  std::unique_ptr<FakePce> fake_pce;
  ASYLO_ASSERT_OK_AND_ASSIGN(fake_pce, FakePce::CreateFromFakePki());

  Targetinfo targetinfo;
  uint16_t pce_svn;
  ASYLO_ASSERT_OK(fake_pce->GetPceTargetinfo(&targetinfo, &pce_svn));

  EXPECT_THAT(targetinfo.reserved1,
              TrivialObjectEq(TrivialZeroObject<UnsafeBytes<2>>()));
  EXPECT_THAT(targetinfo.reserved2,
              TrivialObjectEq(TrivialZeroObject<UnsafeBytes<8>>()));
  EXPECT_THAT(targetinfo.reserved3,
              TrivialObjectEq(TrivialZeroObject<UnsafeBytes<384>>()));
  EXPECT_THAT(targetinfo.attributes, Eq(SecsAttributeSet::GetMustBeSetBits()));
  EXPECT_THAT(targetinfo.miscselect, Eq(0));
  EXPECT_THAT(pce_svn, Eq(FakePce::kPceSvn));
}

TEST(FakePceTest, PceSignReportSuccess) {
  const uint16_t kPceSvn = 9;

  std::unique_ptr<SigningKey> pck_priv;
  ASYLO_ASSERT_OK_AND_ASSIGN(pck_priv, EcdsaP256Sha256SigningKey::Create());

  std::unique_ptr<VerifyingKey> pck_pub;
  ASYLO_ASSERT_OK_AND_ASSIGN(pck_pub, pck_priv->GetVerifyingKey());

  FakePce fake_pce(std::move(pck_priv), kPceSvn, /*pce_id=*/1,
                   UnsafeBytes<kPpidSize>("PPIDppidPPIDppid"));

  Report report = TrivialRandomObject<Report>();
  UnsafeBytes<kCpusvnSize> target_cpu_svn = {};
  std::string pck_signature;

  ASYLO_ASSERT_OK(
      fake_pce.PceSignReport(report, kPceSvn, target_cpu_svn, &pck_signature));
  Signature signature;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signature, CreateSignatureFromPckEcdsaP256Sha256Signature(pck_signature));

  ASYLO_EXPECT_OK(pck_pub->Verify(
      ByteContainerView(&report.body, sizeof(report.body)), signature));
}

TEST(FakePceTest, GetPceInfoSuccess) {
  std::unique_ptr<FakePce> fake_pce;
  ASYLO_ASSERT_OK_AND_ASSIGN(fake_pce, FakePce::CreateFromFakePki());

  std::unique_ptr<RsaOaepDecryptionKey> rsa_ppiddk;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      rsa_ppiddk, RsaOaepDecryptionKey::CreateRsa3072OaepDecryptionKey(SHA256));

  std::unique_ptr<AsymmetricEncryptionKey> rsa_ppidek;
  ASYLO_ASSERT_OK_AND_ASSIGN(rsa_ppidek, rsa_ppiddk->GetEncryptionKey());

  std::vector<uint8_t> ppid_encryption_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      ppid_encryption_key,
      SerializeRsa3072PublicKey(
          reinterpret_cast<RsaOaepEncryptionKey *>(rsa_ppidek.get())
              ->GetRsaPublicKey()));

  Report report = TrivialRandomObject<Report>();
  AsymmetricEncryptionScheme ppid_encryption_scheme = RSA3072_OAEP;
  std::string ppid_encrypted;
  uint16_t pce_svn;
  uint16_t pce_id;
  SignatureScheme signature_scheme;

  ASYLO_ASSERT_OK(fake_pce->GetPceInfo(report, ppid_encryption_key,
                                       ppid_encryption_scheme, &ppid_encrypted,
                                       &pce_svn, &pce_id, &signature_scheme));

  EXPECT_THAT(pce_svn, Eq(FakePce::kPceSvn));
  EXPECT_THAT(pce_id, Eq(FakePce::kPceId));
  EXPECT_THAT(signature_scheme, Eq(ECDSA_P256_SHA256));

  CleansingVector<uint8_t> ppid;
  ASYLO_ASSERT_OK(rsa_ppiddk->Decrypt(ppid_encrypted, &ppid));
  EXPECT_THAT(ppid.data(), MemEq(&FakePce::kPpid, sizeof(FakePce::kPpid)));
}

TEST(FakePceTest, GetQeTargetinfoIsUnimplemented) {
  std::unique_ptr<FakePce> fake_pce;
  ASYLO_ASSERT_OK_AND_ASSIGN(fake_pce, FakePce::CreateFromFakePki());

  EXPECT_THAT(fake_pce->GetQeTargetinfo(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(FakePceTest, GetQeQuoteIsUnimplemented) {
  std::unique_ptr<FakePce> fake_pce;
  ASYLO_ASSERT_OK_AND_ASSIGN(fake_pce, FakePce::CreateFromFakePki());

  Report report = TrivialRandomObject<Report>();
  EXPECT_THAT(fake_pce->GetQeQuote(report),
              StatusIs(absl::StatusCode::kUnimplemented));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
