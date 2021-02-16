/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/identity/attestation/sgx/internal/sgx_remote_assertion_generator_impl.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <google/protobuf/repeated_field.h>
#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/time/time.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/grpc/auth/enclave_channel_credentials.h"
#include "asylo/grpc/auth/enclave_server_credentials.h"
#include "asylo/grpc/auth/null_credentials_options.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/attestation/sgx/internal/sgx_remote_assertion_generator_client.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/init.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/self_identity.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/test/util/enclave_assertion_authority_configs.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"
#include "asylo/util/thread.h"
#include "include/grpcpp/grpcpp.h"

namespace asylo {
namespace sgx {
namespace {

using CertsAndSigningKeyPair =
    std::pair<std::vector<CertificateChain>, std::unique_ptr<SigningKey>>;
using CertsAndVerifyingKeyPair =
    std::pair<std::vector<CertificateChain>, std::unique_ptr<VerifyingKey>>;

constexpr char kAddress[] = "[::1]";
constexpr char kUserData[] = "Dudley Bose";
constexpr char kCertificateChain1[] = R"proto(
  certificates: { format: X509_DER data: "child" }
  certificates: { format: X509_DER data: "root" }
)proto";
constexpr char kCertificateChain2[] = R"proto(
  certificates: { format: X509_DER data: "child2" }
  certificates: { format: X509_DER data: "root2" }
)proto";
constexpr char kCertificate[] = "Certificate";
constexpr int kNumThreads = 20;

const int64_t kDeadlineMicros = absl::Seconds(5) / absl::Microseconds(1);

class SgxRemoteAssertionGeneratorImplTest : public testing::Test {
 protected:
  static void SetUpTestSuite() {
    // Set up assertion authority configs.
    std::vector<asylo::EnclaveAssertionAuthorityConfig> authority_configs = {
        GetNullAssertionAuthorityTestConfig(),
        GetSgxLocalAssertionAuthorityTestConfig()};

    // Explicitly initialize all assertion authorities.
    ASSERT_THAT(InitializeEnclaveAssertionAuthorities(
                    authority_configs.cbegin(), authority_configs.cend()),
                IsOk());
  }

  void SetUp() override {
    // Avoid calling GetSelfIdentity() multiple times within one test case
    // because each call generates a new random identity.
    self_identity_ = GetSelfIdentity();
  }

  asylo::StatusOr<std::unique_ptr<SgxRemoteAssertionGeneratorImpl>>
  CreateServiceWithKeyAndCertificate() {
    CertificateChain certificate_chain;
    if (!google::protobuf::TextFormat::ParseFromString(kCertificateChain1,
                                             &certificate_chain)) {
      return Status(absl::StatusCode::kInternal,
                    "Failed to parse text certificate chain proto");
    }
    certificate_chains_.push_back(certificate_chain);

    // Use a randomly-generated signing key.
    std::unique_ptr<SigningKey> signing_key;
    ASYLO_ASSIGN_OR_RETURN(signing_key, EcdsaP256Sha256SigningKey::Create());
    ASYLO_ASSIGN_OR_RETURN(verifying_key_, signing_key->GetVerifyingKey());
    signature_scheme_ = signing_key->GetSignatureScheme();

    return absl::make_unique<SgxRemoteAssertionGeneratorImpl>(
        std::move(signing_key), certificate_chains_);
  }

  void TearDown() override {
    if (server_) {
      server_->Shutdown();
    }
  }

  // Starts a gRPC server that hosts |service|. The server is hosted on a
  // randomly-selected port with |server_credentials|. This method saves the
  // final server address in server_address_.
  void SetUpServer(
      SgxRemoteAssertionGeneratorImpl *service,
      const std::shared_ptr<::grpc::ServerCredentials> &server_credentials) {
    ::grpc::ServerBuilder builder;
    builder.RegisterService(service);

    int port = 0;
    builder.AddListeningPort(absl::StrCat(kAddress, ":", port),
                             server_credentials, &port);
    server_ = builder.BuildAndStart();
    ASSERT_NE(port, 0);

    server_address_ = absl::StrCat(kAddress, ":", port);
  }

  // Starts a gRPC client that connects to the server using
  // |channel_credentials|. Uses the client to make a GenerateSgxRemoteAssertion
  // RPC and returns the result of the RPC.
  StatusOr<RemoteAssertion> GenerateSgxRemoteAssertion(
      const std::shared_ptr<::grpc::ChannelCredentials> &channel_credentials) {
    std::shared_ptr<::grpc::Channel> channel =
        ::grpc::CreateChannel(server_address_, channel_credentials);

    gpr_timespec absolute_deadline =
        gpr_time_add(gpr_now(GPR_CLOCK_REALTIME),
                     gpr_time_from_micros(kDeadlineMicros, GPR_TIMESPAN));
    if (!channel->WaitForConnected(absolute_deadline)) {
      return Status(absl::StatusCode::kInternal, "Failed to connect to server");
    }

    SgxRemoteAssertionGeneratorClient client(channel);
    return client.GenerateSgxRemoteAssertion(kUserData);
  }

  bool CheckCertificateChainsEqual(
      const std::vector<CertificateChain> &certificate_chains1,
      const google::protobuf::RepeatedPtrField<CertificateChain> &certificate_chains2) {
    // Optimization: Compare manually instead of using MessageDifferencer, as it
    // is expensive. Simply comparing format and data is sufficient, and cheaper
    // by at least an order of magnitude.
    if (certificate_chains1.size() != certificate_chains2.size()) {
      return false;
    }

    for (size_t i = 0; i < certificate_chains1.size(); ++i) {
      if (certificate_chains1[i].certificates_size() !=
          certificate_chains2[i].certificates_size()) {
        return false;
      }

      for (size_t j = 0; j < certificate_chains1[i].certificates_size(); ++j) {
        const auto &certificate1 = certificate_chains1[i].certificates(j);
        const auto &certificate2 = certificate_chains2[i].certificates(j);
        if (certificate1.format() != certificate2.format() ||
            certificate1.data() != certificate2.data()) {
          return false;
        }
      }
    }

    return true;
  }

  void RemoteAssertionCanBeVerifiedByOneKeyAndCerts(
      const RemoteAssertion &assertion,
      const std::vector<CertsAndVerifyingKeyPair>
          &certs_and_verifying_key_pairs) {
    for (const CertsAndVerifyingKeyPair &certs_and_verifying_key_pair :
         certs_and_verifying_key_pairs) {
      std::vector<CertificateChain> certificate_chains =
          certs_and_verifying_key_pair.first;
      if (CheckCertificateChainsEqual(certificate_chains,
                                      assertion.certificate_chains())) {
        VerifyRemoteAssertion(assertion, certificate_chains,
                              *certs_and_verifying_key_pair.second);
        break;
      }
    }
  }

  void VerifyRemoteAssertion(
      const RemoteAssertion &assertion,
      const std::vector<CertificateChain> &certificate_chains,
      const VerifyingKey &verifying_key) {
    EXPECT_EQ(assertion.verifying_key().signature_scheme(), signature_scheme_);
    EXPECT_EQ(assertion.certificate_chains().size(), certificate_chains.size());
    for (size_t i = 0; i < assertion.certificate_chains().size(); ++i) {
      EXPECT_THAT(assertion.certificate_chains(i),
                  EqualsProto(certificate_chains.at(i)));
    }
    RemoteAssertionPayload payload;
    EXPECT_TRUE(payload.ParseFromString(assertion.payload()));
    EXPECT_THAT(payload.identity(), EqualsProto(self_identity_->sgx_identity));
    EXPECT_EQ(payload.user_data(), kUserData);
    EXPECT_EQ(payload.signature_scheme(), signature_scheme_);

    ASYLO_EXPECT_OK(verifying_key.Verify(payload.SerializeAsString(),
                                         assertion.signature()));
  }

  SignatureScheme signature_scheme_;
  std::unique_ptr<VerifyingKey> verifying_key_;
  std::vector<CertificateChain> certificate_chains_;
  std::unique_ptr<::grpc::Server> server_;
  std::string server_address_;
  const SelfIdentity *self_identity_;
};

TEST_F(SgxRemoteAssertionGeneratorImplTest,
       ServerWithoutAttestationKeyGenerateSgxRemoteAssertionFails) {
  // Configure the server and the peer to use bidirectional authentication based
  // on SGX local attestation. SGX-remote-assertion generation is authorized in
  // this case.
  std::shared_ptr<::grpc::ServerCredentials> server_credentials =
      EnclaveServerCredentials(BidirectionalSgxLocalCredentialsOptions());
  auto service = absl::make_unique<SgxRemoteAssertionGeneratorImpl>();
  SetUpServer(service.get(), server_credentials);

  std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
      EnclaveChannelCredentials(BidirectionalSgxLocalCredentialsOptions());
  EXPECT_THAT(GenerateSgxRemoteAssertion(channel_credentials),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(SgxRemoteAssertionGeneratorImplTest,
       GenerateSgxRemoteAssertionSucceeds) {
  // Configure the server and the peer to use bidirectional authentication based
  // on SGX local attestation. SGX-remote-assertion generation is authorized in
  // this case, and should produce a valid remote assertion.
  std::shared_ptr<::grpc::ServerCredentials> server_credentials =
      EnclaveServerCredentials(BidirectionalSgxLocalCredentialsOptions());
  std::unique_ptr<SgxRemoteAssertionGeneratorImpl> service;
  ASYLO_ASSERT_OK_AND_ASSIGN(service, CreateServiceWithKeyAndCertificate());
  SetUpServer(service.get(), server_credentials);

  std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
      EnclaveChannelCredentials(BidirectionalSgxLocalCredentialsOptions());
  RemoteAssertion assertion;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion,
                             GenerateSgxRemoteAssertion(channel_credentials));
  EXPECT_NO_FATAL_FAILURE(
      VerifyRemoteAssertion(assertion, certificate_chains_, *verifying_key_));
}

TEST_F(SgxRemoteAssertionGeneratorImplTest,
       UpdateSigningKeyAndCertificateChainsOnNoKeyServerSucceeds) {
  // Configure the server and the peer to use bidirectional authentication based
  // on SGX local attestation. SGX-remote-assertion generation is authorized in
  // this case.
  std::shared_ptr<::grpc::ServerCredentials> server_credentials =
      EnclaveServerCredentials(BidirectionalSgxLocalCredentialsOptions());
  auto service = absl::make_unique<SgxRemoteAssertionGeneratorImpl>();
  SetUpServer(service.get(), server_credentials);

  std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
      EnclaveChannelCredentials(BidirectionalSgxLocalCredentialsOptions());

  // Update the server to use new signing key and certificate chains.
  std::unique_ptr<SigningKey> signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(signing_key, EcdsaP256Sha256SigningKey::Create());
  signature_scheme_ = signing_key->GetSignatureScheme();
  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(verifying_key, signing_key->GetVerifyingKey());
  std::vector<CertificateChain> certificate_chains;
  CertificateChain certificate_chain;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kCertificateChain1,
                                                  &certificate_chain));
  certificate_chains.push_back(certificate_chain);
  service->UpdateSigningKeyAndCertificateChains(std::move(signing_key),
                                                certificate_chains);

  // Get assertion generated using new signing key and certificate chains and
  // verify the result.
  RemoteAssertion assertion;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion,
                             GenerateSgxRemoteAssertion(channel_credentials));
  EXPECT_NO_FATAL_FAILURE(
      VerifyRemoteAssertion(assertion, certificate_chains, *verifying_key));
}

TEST_F(SgxRemoteAssertionGeneratorImplTest,
       UpdateSigningKeyAndCertificateChainsSucceeds) {
  // Configure the server and the peer to use bidirectional authentication based
  // on SGX local attestation. SGX-remote-assertion generation is authorized in
  // this case, and should produce a valid remote assertion.
  std::shared_ptr<::grpc::ServerCredentials> server_credentials =
      EnclaveServerCredentials(BidirectionalSgxLocalCredentialsOptions());
  std::unique_ptr<SgxRemoteAssertionGeneratorImpl> service;
  ASYLO_ASSERT_OK_AND_ASSIGN(service, CreateServiceWithKeyAndCertificate());
  SetUpServer(service.get(), server_credentials);

  std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
      EnclaveChannelCredentials(BidirectionalSgxLocalCredentialsOptions());
  RemoteAssertion assertion;
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion,
                             GenerateSgxRemoteAssertion(channel_credentials));
  VerifyRemoteAssertion(assertion, certificate_chains_, *verifying_key_);

  // Update the server to use new signing key and certificate chains.
  std::unique_ptr<SigningKey> signing_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(signing_key, EcdsaP256Sha256SigningKey::Create());
  std::unique_ptr<VerifyingKey> verifying_key;
  ASYLO_ASSERT_OK_AND_ASSIGN(verifying_key, signing_key->GetVerifyingKey());
  std::vector<CertificateChain> certificate_chains;
  CertificateChain certificate_chain;
  ASSERT_TRUE(google::protobuf::TextFormat::ParseFromString(kCertificateChain2,
                                                  &certificate_chain));
  certificate_chains.push_back(certificate_chain);
  service->UpdateSigningKeyAndCertificateChains(std::move(signing_key),
                                                certificate_chains);

  // Get assertion generated using new signing key and certificate chains and
  // verify the result.
  assertion.Clear();
  ASYLO_ASSERT_OK_AND_ASSIGN(assertion,
                             GenerateSgxRemoteAssertion(channel_credentials));
  EXPECT_NO_FATAL_FAILURE(
      VerifyRemoteAssertion(assertion, certificate_chains, *verifying_key));
}

TEST_F(SgxRemoteAssertionGeneratorImplTest,
       UpdateSigningKeyAndCertificateChainsMultiThreadedSucceeds) {
  std::shared_ptr<::grpc::ServerCredentials> server_credentials =
      EnclaveServerCredentials(BidirectionalSgxLocalCredentialsOptions());
  std::unique_ptr<SgxRemoteAssertionGeneratorImpl> service;
  ASYLO_ASSERT_OK_AND_ASSIGN(service, CreateServiceWithKeyAndCertificate());
  SetUpServer(service.get(), server_credentials);

  std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
      EnclaveChannelCredentials(BidirectionalSgxLocalCredentialsOptions());

  std::vector<CertsAndSigningKeyPair> certs_signing_key_pairs;
  std::vector<CertsAndVerifyingKeyPair> certs_verifying_key_pairs;
  certs_verifying_key_pairs.push_back(
      std::make_pair(certificate_chains_, std::move(verifying_key_)));

  certs_signing_key_pairs.reserve(kNumThreads);
  std::vector<Thread> threads;
  threads.reserve(kNumThreads);
  for (int i = 0; i < kNumThreads; ++i) {
    std::unique_ptr<SigningKey> signing_key;
    ASYLO_ASSERT_OK_AND_ASSIGN(signing_key,
                               EcdsaP256Sha256SigningKey::Create());
    std::unique_ptr<VerifyingKey> verifying_key;
    ASYLO_ASSERT_OK_AND_ASSIGN(verifying_key, signing_key->GetVerifyingKey());

    std::vector<CertificateChain> certificate_chains(1);
    Certificate *certificate = certificate_chains.back().add_certificates();
    certificate->set_format(Certificate::X509_DER);
    certificate->set_data(absl::StrCat(kCertificate, i));

    certs_verifying_key_pairs.push_back(
        std::make_pair(certificate_chains, std::move(verifying_key)));
    certs_signing_key_pairs.push_back(
        std::make_pair(certificate_chains, std::move(signing_key)));
  }

  std::shared_ptr<::grpc::Channel> channel =
      ::grpc::CreateChannel(server_address_, channel_credentials);
  gpr_timespec absolute_deadline =
      gpr_time_add(gpr_now(GPR_CLOCK_REALTIME),
                   gpr_time_from_micros(kDeadlineMicros, GPR_TIMESPAN));
  ASSERT_TRUE(channel->WaitForConnected(absolute_deadline));

  SgxRemoteAssertionGeneratorImpl *service_ptr = service.get();
  for (int i = 0; i < kNumThreads; ++i) {
    threads.emplace_back([&certs_signing_key_pairs, &certs_verifying_key_pairs,
                          &channel, service_ptr, this, i] {
      SgxRemoteAssertionGeneratorClient client(channel);

      service_ptr->UpdateSigningKeyAndCertificateChains(
          std::move(certs_signing_key_pairs[i].second),
          certs_signing_key_pairs[i].first);

      // Increases the chance that the server is contacted in its various
      // intermediate states.
      constexpr int kNumAssertionChecks = 15;
      for (int j = 0; j < kNumAssertionChecks; ++j) {
        RemoteAssertion assertion;
        ASYLO_ASSERT_OK_AND_ASSIGN(
            assertion, client.GenerateSgxRemoteAssertion(kUserData));
        ASSERT_NO_FATAL_FAILURE(RemoteAssertionCanBeVerifiedByOneKeyAndCerts(
            assertion, certs_verifying_key_pairs));
      }
    });
  }

  for (auto &thread : threads) {
    thread.Join();
  }
}

// The following tests verify that other configurations of the server and peer
// credentials result in the expected RPC errors. Note that these credentials
// configurations are not expected to be used with the
// SgxRemoteAssertionGenerator service, but these tests verify that they produce
// the expected error conditions in case of misconfiguration.

TEST_F(SgxRemoteAssertionGeneratorImplTest,
       GenerateSgxRemoteAssertionPermissionDeniedWithoutSgxIdentity) {
  // Configure the server and the peer to use bidirectional authentication based
  // on null identity. Although this configuration will result in an EKEP-based
  // connection, the peer will be lacking an SGX identity and, consequently,
  // will be unauthorized to obtain an SGX remote assertion.
  std::shared_ptr<::grpc::ServerCredentials> server_credentials =
      EnclaveServerCredentials(BidirectionalNullCredentialsOptions());
  std::unique_ptr<SgxRemoteAssertionGeneratorImpl> service;
  ASYLO_ASSERT_OK_AND_ASSIGN(service, CreateServiceWithKeyAndCertificate());
  SetUpServer(service.get(), server_credentials);

  std::shared_ptr<::grpc::ChannelCredentials> credentials =
      EnclaveChannelCredentials(BidirectionalNullCredentialsOptions());
  auto result = GenerateSgxRemoteAssertion(credentials);

  ASSERT_THAT(result, StatusIs(absl::StatusCode::kPermissionDenied));
}

TEST_F(SgxRemoteAssertionGeneratorImplTest,
       GenerateSgxRemoteAssertionInternalErrorWithoutEkepConnection) {
  // Configure the server and the peer to use insecure credentials. This
  // configuration will result in improperly authenticated peers that do not
  // have any enclave authentication information.
  std::shared_ptr<::grpc::ServerCredentials> server_credentials =
      ::grpc::InsecureServerCredentials();
  std::unique_ptr<SgxRemoteAssertionGeneratorImpl> service;
  ASYLO_ASSERT_OK_AND_ASSIGN(service, CreateServiceWithKeyAndCertificate());
  SetUpServer(service.get(), server_credentials);

  std::shared_ptr<::grpc::ChannelCredentials> credentials =
      ::grpc::InsecureChannelCredentials();
  auto result = GenerateSgxRemoteAssertion(credentials);

  ASSERT_THAT(result, StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
