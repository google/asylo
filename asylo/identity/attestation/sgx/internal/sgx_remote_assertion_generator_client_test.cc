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

#include "asylo/identity/attestation/sgx/internal/sgx_remote_assertion_generator_client.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion.pb.h"
#include "asylo/identity/attestation/sgx/internal/sgx_remote_assertion_generator_mock.grpc.pb.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/support/status.h"

namespace asylo {
namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

constexpr char kUserData[] = "Foo Bar Baz";

// Tests that the SgxRemoteAssertionGeneratorClient correctly propagates the
// result from a successful GenerateSgxRemoteAssertion RPC.
TEST(SgxRemoteAssertionGeneratorClientTest,
     GenerateSgxRemoteAssertionSucceeds) {
  auto mock_stub =
      absl::make_unique<MockSgxRemoteAssertionGeneratorStub>();

  GenerateSgxRemoteAssertionRequest request;
  request.set_user_data(kUserData);
  GenerateSgxRemoteAssertionResponse response;
  sgx::RemoteAssertion &assertion = *response.mutable_assertion();
  assertion.set_payload("payload");
  assertion.set_signature("signature");
  AsymmetricSigningKeyProto *verifying_key = assertion.mutable_verifying_key();
  verifying_key->set_key_type(AsymmetricSigningKeyProto::VERIFYING_KEY);
  verifying_key->set_signature_scheme(ECDSA_P256_SHA256);
  verifying_key->set_encoding(ASYMMETRIC_KEY_PEM);
  verifying_key->set_key("key data");
  Certificate &certificate =
      *assertion.add_certificate_chains()->add_certificates();
  certificate.set_format(Certificate::X509_DER);
  certificate.set_data("certificate data");

  EXPECT_CALL(*mock_stub,
              GenerateSgxRemoteAssertion(_, EqualsProto(request), _))
      .WillOnce(DoAll(SetArgPointee<2>(response), Return(::grpc::Status::OK)));

  SgxRemoteAssertionGeneratorClient client(
      std::unique_ptr<SgxRemoteAssertionGenerator::StubInterface>(
          std::move(mock_stub)));
  auto result = client.GenerateSgxRemoteAssertion(kUserData);

  ASSERT_THAT(result, IsOk());
  EXPECT_THAT(result.value(), EqualsProto(assertion));
}

// Tests that the SgxRemoteAssertionGeneratorClient correctly propagates the
// RPC status from a failed GenerateSgxRemoteAssertion RPC.
TEST(SgxRemoteAssertionGeneratorClientTest, GenerateSgxRemoteAssertionFails) {
  auto mock_stub =
      absl::make_unique<MockSgxRemoteAssertionGeneratorStub>();

  GenerateSgxRemoteAssertionRequest request;
  request.set_user_data(kUserData);

  EXPECT_CALL(*mock_stub,
              GenerateSgxRemoteAssertion(_, EqualsProto(request), _))
      .WillOnce(Return(::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED,
                                      "Peer does not have SGX code identity")));

  SgxRemoteAssertionGeneratorClient client(
      std::unique_ptr<SgxRemoteAssertionGenerator::StubInterface>(
          std::move(mock_stub)));
  EXPECT_THAT(client.GenerateSgxRemoteAssertion(kUserData),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

}  // namespace
}  // namespace asylo
