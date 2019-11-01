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
#include "absl/strings/escaping.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/identity/sgx/remote_assertion.pb.h"
#include "asylo/identity/sgx/sgx_identity.pb.h"
#include "asylo/identity/sgx/sgx_identity_util.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"

namespace asylo {
namespace sgx {
namespace {

// This certificate chain mimics relevant properties of the Intel certificate
// chain, including that it is made of valid X.509 certificates and a valid
// Attestation Key certificate.
constexpr char kRequiredRootCertificate[] =
    R"(-----BEGIN CERTIFICATE-----
MIIB+TCCAaCgAwIBAgIRYXN5bG8gdGVzdCBjZXJ0IDEwCgYIKoZIzj0EAwIwVDEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMREwDwYDVQQHDAhLaXJrbGFuZDEOMAwG
A1UECwwFQXN5bG8xFTATBgNVBAMMDFRlc3QgUm9vdCBDQTAeFw0xOTA1MDMxODEz
MjBaFw0xOTA1MDQxODEzMjBaMFQxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTER
MA8GA1UEBwwIS2lya2xhbmQxDjAMBgNVBAsMBUFzeWxvMRUwEwYDVQQDDAxUZXN0
IFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATq7aUQPokZT0O/4NhE
8+efAAlX/DySN8fqjdzWfiLHXNdRGeqaoC92zsrLvxsv5hxp/J7q2h/imlZ9bOtG
jha9o1MwUTAdBgNVHQ4EFgQUcN3IQ2MRK/eH7KSED3q+9it1/a0wHwYDVR0jBBgw
FoAUcN3IQ2MRK/eH7KSED3q+9it1/a0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO
PQQDAgNHADBEAiAcTIfVdk3xKvgka85I96uGdWSDYWYlShzXaUDB04crYAIgBtdS
1WkwPDgfyWZcUO+ImDG38iEOwuPXSk18GRwMrFY=
-----END CERTIFICATE-----)";

constexpr char kIntermediateCertificate[] =
    R"(-----BEGIN CERTIFICATE-----
MIIBpzCCAU4CFA2VFTA4Zr7JFVJCi3pY0SOCCdO7MAoGCCqGSM49BAMCMFQxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIDAJXQTERMA8GA1UEBwwIS2lya2xhbmQxDjAMBgNV
BAsMBUFzeWxvMRUwEwYDVQQDDAxUZXN0IFJvb3QgQ0EwHhcNMTkwNTA3MTkxMTQ5
WhcNMTkwNjA2MTkxMTQ5WjBZMQswCQYDVQQGEwJVUzELMAkGA1UECAwCV0ExETAP
BgNVBAcMCEtpcmtsYW5kMQ4wDAYDVQQLDAVBc3lsbzEaMBgGA1UEAwwRVGVzdCBJ
bnRlcm1lZGlhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQAeZRSJGNpEEUs
CI09eR7OP9p1RmA+FP52/K/N11/Lfn1jv7MqiUeQv28Sj+affaL4U5TS+sQggwUQ
AhLBDyLZMAoGCCqGSM49BAMCA0cAMEQCIBjabAR3EHqV/HQoZqAfnIbJ5DeSiJ/5
mPeRFjP+ta25AiANztrYLvL9EPathyAKkYeTVF2Ybmu77zrmL5g3lUlQ3g==
-----END CERTIFICATE-----)";

constexpr char kSecondIntermediateCertificate[] =
    R"(-----BEGIN CERTIFICATE-----
MIIBsTCCAVcCFANGO/7xEmkKZTrRmnVs6ChLYYbqMAoGCCqGSM49BAMCMFkxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIDAJXQTERMA8GA1UEBwwIS2lya2xhbmQxDjAMBgNV
BAsMBUFzeWxvMRowGAYDVQQDDBFUZXN0IEludGVybWVkaWF0ZTAeFw0xOTA1MDcx
OTM2NDVaFw0xOTA2MDYxOTM2NDVaMF0xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApX
YXNoaW5ndG9uMREwDwYDVQQHDAhLaXJrbGFuZDEOMAwGA1UECwwFQXN5bG8xFjAU
BgNVBAMMDUVuZCBVc2VyIENlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASQ
k96GaZ45U/PP4xB/b4gIz4Klm9AWrsA0NhWSL9pz+MsSAYkoBIgS1Lc7dlp2nRzW
eYSH07qoYfPYcp4nBQRzMAoGCCqGSM49BAMCA0gAMEUCIQCymQ9ERdjk+DlZ5v3y
kmNQbC8XbmwBZfI6i+2XM1z4tQIgDj+9hkLhd2pCK9XhSwMsPojKiBvU/QLIkCKN
5WFOMbA=
-----END CERTIFICATE-----)";

constexpr char kAttestationKeyCertificateHex[] =
    "0ab3030ab00300000000000000000000000000000000010000000000000000000000000000"
    "000000000000000000000000000000000027000000000000002700000000000000b0f58825"
    "c26d5277c20aaaef3b3493aafcef70f36957b3d90712ee2c96b3f652000000000000000000"
    "0000000000000000000000000000000000000000000000bdf1e39990510cf9429fae5fa64b"
    "6cd39a67c99958a0103ba9be7948aae7de0c00000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000"
    "0000001e2c389c000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000164dc4494a164c"
    "30afafb33f4bbbef77506c65b1d48fe4a47729594a86e2affa000000000000000000000000"
    "000000004153594c4f205349474e5245504f52540000000000000000000000000000000000"
    "000000000000000000000000000000e2543dbcb2c76a13001e0a9aa072526912dd010ac401"
    "0a63080210011802225b3059301306072a8648ce3d020106082a8648ce3d03010703420004"
    "bb69f2e901d926d9d7e7469d690176f904148b96887e890e5bb1b21c6018c85333f65500ca"
    "2699d4702ec98986cc0c10a0ff13ae37517aae3926328c3f0b82681230417373657274696f"
    "6e2047656e657261746f7220456e636c617665204174746573746174696f6e204b65792076"
    "302e311a2b417373657274696f6e2047656e657261746f7220456e636c6176652041747465"
    "73746174696f6e204b65791214504345205369676e205265706f72742076302e311a480801"
    "12440a20a6a6e3bf578aa7bb236bae4cf90eb2d69ce703c35354c860826f8a8d424d9b7d12"
    "20b375ee4ba12e616889ebb0ad47489c73c7977fa053c40476c2ee9852f1279d51";

constexpr char kUserData[] = "User Data";

Certificate Cert(const std::string &data,
                 Certificate::CertificateFormat format) {
  Certificate root_cert;
  root_cert.set_format(format);
  root_cert.set_data(data);
  return root_cert;
}

CertificateChain CreateValidCertChain() {
  CertificateChain chain;
  *chain.add_certificates() =
      Cert(absl::HexStringToBytes(kAttestationKeyCertificateHex),
           Certificate::SGX_ATTESTATION_KEY_CERTIFICATE);
  *chain.add_certificates() =
      Cert(kSecondIntermediateCertificate, Certificate::X509_PEM);
  *chain.add_certificates() =
      Cert(kIntermediateCertificate, Certificate::X509_PEM);
  *chain.add_certificates() =
      Cert(kRequiredRootCertificate, Certificate::X509_PEM);

  return chain;
}

TEST(RemoteAssertionUtilTest, MakeRemoteAssertionSucceeds) {
  std::vector<CertificateChain> certificate_chains = {CreateValidCertChain()};

  // Random signing key.
  std::unique_ptr<EcdsaP256Sha256SigningKey> signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(signing_key, EcdsaP256Sha256SigningKey::Create());

  // Current enclave's SGX identity.
  const SgxIdentity identity = GetSelfSgxIdentity();

  RemoteAssertion assertion;
  ASSERT_THAT(MakeRemoteAssertion(kUserData, identity, *signing_key,
                                  certificate_chains, &assertion),
              IsOk());

  std::unique_ptr<VerifyingKey> expected_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(expected_verifying_key,
                             signing_key->GetVerifyingKey());
  std::unique_ptr<VerifyingKey> actual_verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      actual_verifying_key,
      EcdsaP256Sha256VerifyingKey::CreateFromProto(assertion.verifying_key()));

  EXPECT_EQ(*actual_verifying_key, *expected_verifying_key);

  EXPECT_EQ(assertion.certificate_chains_size(), certificate_chains.size());

  RemoteAssertionPayload payload;
  ASSERT_TRUE(payload.ParseFromString(assertion.payload()));
  EXPECT_EQ(payload.signature_scheme(), signing_key->GetSignatureScheme());
  EXPECT_EQ(payload.user_data(), kUserData);
  EXPECT_THAT(payload.identity(), EqualsProto(identity));

  ASYLO_EXPECT_OK(
      actual_verifying_key->Verify(assertion.payload(), assertion.signature()));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
