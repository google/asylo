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
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/sgx/pce_util.h"
#include "asylo/identity/sgx/secs_attributes.h"
#include "asylo/test/util/memory_matchers.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace sgx {
namespace {

using ::testing::Eq;

constexpr uint16_t kPceSvn = 7;

TEST(FakePceTest, SetEnclaveDirSucceess) {
  FakePce fake_pce(/*pck=*/nullptr, kPceSvn);

  ASYLO_EXPECT_OK(fake_pce.SetEnclaveDir("/foo/bar"));
}

TEST(FakePceTest, GetPceTargetinfoSuccess) {
  FakePce fake_pce(/*pck=*/nullptr, kPceSvn);

  Targetinfo targetinfo;
  uint16_t pce_svn;
  ASYLO_ASSERT_OK(fake_pce.GetPceTargetinfo(&targetinfo, &pce_svn));

  EXPECT_THAT(targetinfo.reserved1,
              TrivialObjectEq(TrivialZeroObject<UnsafeBytes<2>>()));
  EXPECT_THAT(targetinfo.reserved2,
              TrivialObjectEq(TrivialZeroObject<UnsafeBytes<8>>()));
  EXPECT_THAT(targetinfo.reserved3,
              TrivialObjectEq(TrivialZeroObject<UnsafeBytes<384>>()));
  EXPECT_THAT(targetinfo.attributes, Eq(SecsAttributeSet::GetMustBeSetBits()));
  EXPECT_THAT(targetinfo.miscselect, Eq(0));
  EXPECT_THAT(pce_svn, Eq(kPceSvn));
}

TEST(FakePceTest, PceSignReportSuccess) {
  std::unique_ptr<SigningKey> pck_priv;
  ASYLO_ASSERT_OK_AND_ASSIGN(pck_priv, EcdsaP256Sha256SigningKey::Create());

  std::unique_ptr<VerifyingKey> pck_pub;
  ASYLO_ASSERT_OK_AND_ASSIGN(pck_pub, pck_priv->GetVerifyingKey());

  FakePce fake_pce(std::move(pck_priv), kPceSvn);

  Report report = TrivialRandomObject<Report>();
  uint16_t target_pce_svn = kPceSvn;
  UnsafeBytes<kCpusvnSize> target_cpu_svn = {};
  std::string pck_signature;

  ASYLO_ASSERT_OK(fake_pce.PceSignReport(report, target_pce_svn, target_cpu_svn,
                                         &pck_signature));
  Signature signature;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      signature, CreateSignatureFromPckEcdsaP256Sha256Signature(pck_signature));

  ASYLO_EXPECT_OK(
      pck_pub->Verify(ByteContainerView(&report, sizeof(Report)), signature));
}

TEST(FakePceTest, GetPceInfoIsUnimplemented) {
  FakePce fake_pce(/*pck=*/nullptr, kPceSvn);

  Report report = TrivialRandomObject<Report>();
  std::vector<uint8_t> ppid_encryption_key;
  AsymmetricEncryptionScheme ppid_encryption_scheme = RSA3072_OAEP;
  std::string ppid_encrypted;
  uint16_t pce_svn;
  uint16_t pce_id;
  SignatureScheme signature_scheme;

  EXPECT_THAT(fake_pce.GetPceInfo(report, ppid_encryption_key,
                                  ppid_encryption_scheme, &ppid_encrypted,
                                  &pce_svn, &pce_id, &signature_scheme),
              StatusIs(error::GoogleError::UNIMPLEMENTED));
}

TEST(FakePceTest, GetQeTargetinfoIsUnimplemented) {
  FakePce fake_pce(/*pck=*/nullptr, kPceSvn);
  EXPECT_THAT(fake_pce.GetQeTargetinfo(),
              StatusIs(error::GoogleError::UNIMPLEMENTED));
}

TEST(FakePceTest, GetQeQuoteIsUnimplemented) {
  FakePce fake_pce(/*pck=*/nullptr, kPceSvn);
  Report report = TrivialRandomObject<Report>();
  EXPECT_THAT(fake_pce.GetQeQuote(report),
              StatusIs(error::GoogleError::UNIMPLEMENTED));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
