/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/identity/sgx/remote_assertion_util.h"

#include <memory>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/identity/sgx/remote_assertion.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace sgx {
namespace {

constexpr char kUserData[] = "User Data";
constexpr char kCertificate[] = "Certificate";

TEST(RemoteAssertionUtilTest, MakeRemoteAssertionSucceeds) {
  std::vector<CertificateChain> certificate_chains;
  certificate_chains.push_back({});
  Certificate *certificate = certificate_chains.back().add_certificates();
  certificate->set_format(Certificate::X509_DER);
  certificate->set_data(kCertificate);

  // Random signing key.
  auto signing_key_result = EcdsaP256Sha256SigningKey::Create();
  EXPECT_THAT(signing_key_result, IsOk());
  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key =
      std::move(signing_key_result).ValueOrDie();

  // Current enclave's code identity.
  CodeIdentity identity;
  SetSelfCodeIdentity(&identity);

  RemoteAssertion assertion;
  ASSERT_THAT(MakeRemoteAssertion(kUserData, identity, *signing_key,
                                  certificate_chains, &assertion),
              IsOk());
  EXPECT_EQ(assertion.signature_scheme(), signing_key->GetSignatureScheme());
  EXPECT_EQ(assertion.certificate_chains_size(), certificate_chains.size());

  RemoteAssertionPayload payload;
  ASSERT_TRUE(payload.ParseFromString(assertion.payload()));
  EXPECT_EQ(payload.signature_scheme(), signing_key->GetSignatureScheme());
  EXPECT_EQ(payload.user_data(), kUserData);
  EXPECT_THAT(payload.identity(), EqualsProto(identity));

  auto verifying_key_result = signing_key->GetVerifyingKey();
  ASSERT_THAT(verifying_key_result, IsOk());

  std::unique_ptr<VerifyingKey> verifying_key =
      std::move(verifying_key_result).ValueOrDie();
  EXPECT_THAT(verifying_key->Verify(assertion.payload(), assertion.signature()),
              IsOk());
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
