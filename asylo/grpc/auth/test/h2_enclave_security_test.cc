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

#include <string>
#include <utility>

#include "asylo/grpc/auth/core/enclave_credentials.h"
#include "asylo/grpc/auth/enclave_credentials_options.h"
#include "asylo/grpc/auth/null_credentials_options.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/init.h"
#include "asylo/identity/platform/sgx/internal/fake_enclave.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/test/util/enclave_assertion_authority_configs.h"
#include "include/grpc/impl/codegen/grpc_types.h"
#include "include/grpc/support/alloc.h"
#include "include/grpc/support/log.h"
#include "src/core/lib/gprpp/host_port.h"
#include "src/core/lib/gprpp/ref_counted_ptr.h"
#include "test/core/end2end/end2end_tests.h"
#include "test/core/util/test_config.h"

namespace asylo {
namespace {

constexpr char kClientAdditionalAuthenticatedData[] = "EKEP client";
constexpr char kServerAdditionalAuthenticatedData[] = "EKEP server";
constexpr char kAddress[] = "[::1]";

struct EnclaveFullStackFixtureData {
  // The address of the server.
  std::string local_address;

  // True if the |local_address| has been updated to contain the server's final
  // port.
  bool port_set;

  // An ACL that will match the enclave identity.
  IdentityAclPredicate identity_acl;
};

IdentityAclPredicate CreateStrictPredicate(const SgxIdentity &identity) {
  StatusOr<SgxIdentityExpectation> expectation_result =
      CreateSgxIdentityExpectation(identity,
                                   SgxIdentityMatchSpecOptions::STRICT_LOCAL);
  GPR_ASSERT(expectation_result.ok());

  StatusOr<EnclaveIdentityExpectation> serialized_expectation_result =
      SerializeSgxIdentityExpectation(std::move(expectation_result).value());
  GPR_ASSERT(serialized_expectation_result.ok());

  IdentityAclPredicate acl;
  *acl.mutable_expectation() = std::move(serialized_expectation_result).value();
  return acl;
}

grpc_end2end_test_fixture CreateFixtureSecureFullstack(
    grpc_channel_args *client_args, grpc_channel_args *server_args) {
  grpc_end2end_test_fixture f;

  EnclaveFullStackFixtureData *fixture_data = new EnclaveFullStackFixtureData;

  // A port of indicates that gRPC should auto-select a port for use. This
  // address is updated with the final port after server initialization.
  fixture_data->local_address = absl::StrFormat("%s:%d", kAddress, 0);
  f.fixture_data = fixture_data;

  // Create a completion queue for the server.
  f.cq = grpc_completion_queue_create_for_next(nullptr);
  f.shutdown_cq = grpc_completion_queue_create_for_pluck(nullptr);

  // The |client| and |server| are configured later in the test.
  f.server = nullptr;
  f.client = nullptr;

  // Set the enclave identity and store in fixture data.
  sgx::FakeEnclave enclave;
  enclave.SetRandomIdentity();
  if (sgx::FakeEnclave::GetCurrentEnclave() != nullptr) {
    sgx::FakeEnclave::ExitEnclave();
  }
  sgx::FakeEnclave::EnterEnclave(enclave);
  fixture_data->identity_acl = CreateStrictPredicate(enclave.GetIdentity());

  return f;
}

// Initializes the channel in fixture |f| using |client_args| and |options|.
void InitClientChannel(EnclaveCredentialsOptions options,
                       grpc_end2end_test_fixture *f,
                       grpc_channel_args *client_args) {
  // The client's AAD is just a fixed string in this test.
  options.additional_authenticated_data = kClientAdditionalAuthenticatedData;

  // Create enclave gRPC channel credentials.
  grpc_core::RefCountedPtr<grpc_enclave_channel_credentials> creds =
      grpc_core::MakeRefCounted<grpc_enclave_channel_credentials>(
          std::move(options));
  GPR_ASSERT(creds != nullptr);

  EnclaveFullStackFixtureData *fixture_data =
      static_cast<EnclaveFullStackFixtureData *>(f->fixture_data);
  GPR_ASSERT(fixture_data->port_set);

  f->client = grpc_secure_channel_create(creds.get(),
                                         fixture_data->local_address.c_str(),
                                         client_args, /*reserved=*/nullptr);
  GPR_ASSERT(f->client != nullptr);
}

// Initializes the client in fixture |f| with |client_args| and bidirectional
// enclave null credentials.
void InitClientEnclaveBidirectionalNullCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *client_args) {
  // Set the client's credentials options. The client supports bidirectional
  // authentication based on null assertions.
  InitClientChannel(BidirectionalNullCredentialsOptions(), f, client_args);
}

// Initializes the client in fixture |f| with |client_args| and bidirectional
// enclave SGX local credentials.
void InitClientEnclaveBidirectionalSgxLocalCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *client_args) {
  // Set the client's credentials options. The client supports bidirectional
  // authentication based on SGX local attestation.
  InitClientChannel(BidirectionalSgxLocalCredentialsOptions(), f, client_args);
}

// Initializes the client in fixture |f| with |client_args| and channel
// credentials that enforce null-identity-based attestation from the server and
// SGX local attestation from the client.
void InitClientEnclaveSelfSgxLocalPeerNullCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *client_args) {
  // Set the client's credentials options. The client offers SGX local
  // credentials and accepts null credentials.
  InitClientChannel(
      SelfSgxLocalCredentialsOptions().Add(PeerNullCredentialsOptions()), f,
      client_args);
}

// Initializes the client in fixture |f| with |client_args| and bidirectional
// enclave SGX local credentials and null credentials.
void InitClientEnclaveBidirectionalNullAndSgxLocalCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *client_args) {
  // Set the client's credentials options. The client supports bidirectional
  // authentication based on SGX local attestation or no authentication.
  InitClientChannel(BidirectionalNullCredentialsOptions().Add(
                        BidirectionalSgxLocalCredentialsOptions()),
                    f, client_args);
}

// Initializes the client in fixture |f| with |client_args| and channel
// credentials that enforce SGX local attestation from the server with an
// ACL and null-identity-based attestation from the client.
void InitClientEnclaveSelfNullPeerSgxLocalWithAcl(
    grpc_end2end_test_fixture *f, grpc_channel_args *client_args) {
  EnclaveCredentialsOptions creds =
      SelfNullCredentialsOptions().Add(PeerSgxLocalCredentialsOptions());

  EnclaveFullStackFixtureData *fixture_data =
      static_cast<EnclaveFullStackFixtureData *>(f->fixture_data);

  creds.peer_acl = fixture_data->identity_acl;

  InitClientChannel(creds, f, client_args);
}

// Initializes the server in fixture |f| using |server_args| and |options|.
void InitServer(EnclaveCredentialsOptions options, grpc_end2end_test_fixture *f,
                grpc_channel_args *server_args) {
  // The server's AAD is just a fixed string in this test.
  options.additional_authenticated_data = kServerAdditionalAuthenticatedData;

  // Create enclave gRPC server credentials.
  grpc_core::RefCountedPtr<grpc_enclave_server_credentials> creds =
      grpc_core::MakeRefCounted<grpc_enclave_server_credentials>(
          std::move(options));
  GPR_ASSERT(creds != nullptr);

  EnclaveFullStackFixtureData *fixture_data =
      static_cast<EnclaveFullStackFixtureData *>(f->fixture_data);
  f->server = grpc_server_create(server_args, /*reserved=*/nullptr);
  grpc_server_register_completion_queue(f->server, f->cq, /*reserved=*/nullptr);

  // Bind the server to the temporary address and update the address with the
  // auto-selected port chosen by the system.
  int port = grpc_server_add_secure_http2_port(
      f->server, fixture_data->local_address.c_str(), creds.get());
  GPR_ASSERT(port != 0);
  fixture_data->local_address = absl::StrFormat("%s:%d", kAddress, port);
  fixture_data->port_set = true;
  grpc_server_start(f->server);
}

// Initializes the server in fixture |f| with |server_args| and bidirectional
// enclave null credentials.
void InitServerEnclaveBidirectionalNullCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *server_args) {
  // Set the server's credentials options. The server supports bidirectional
  // authentication based on null assertions.
  InitServer(BidirectionalNullCredentialsOptions(), f, server_args);
}

// Initializes the server in fixture |f| with |server_args| and bidirectional
// enclave SGX local credentials.
void InitServerEnclaveBidirectionalSgxLocalCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *server_args) {
  // Set the server's credentials options. The server supports bidirectional
  // authentication based on SGX local attestation.
  InitServer(BidirectionalSgxLocalCredentialsOptions(), f, server_args);
}

// Initializes the server in fixture |f| with |server_args| and server
// credentials that enforce null-identity-based attestation from the server and
// SGX local attestation from the client.
void InitServerEnclaveSelfNullPeerSgxLocalCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *server_args) {
  // Set the server's credentials options. The server offers null credentials
  // and accepts SGX local credentials.
  InitServer(SelfNullCredentialsOptions().Add(PeerSgxLocalCredentialsOptions()),
             f, server_args);
}

// Initializes the server in fixture |f| with |server_args| and server
// credentials that enforce SGX local attestation from the server and
// null-identity-based attestation from the client.
void InitServerEnclaveSelfSgxLocalPeerNullCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *server_args) {
  // Set the server's credentials options. The server offers SGX local
  // credentials and accepts null credentials.
  InitServer(SelfSgxLocalCredentialsOptions().Add(PeerNullCredentialsOptions()),
             f, server_args);
}

// Initializes the server in fixture |f| with |server_args| and server
// credentials that enforce null-identity-based attestation from the server and
// SGX local attestation from the client, as well as an ACL on the client.
void InitServerEnclaveSelfNullPeerSgxLocalWithAcl(
    grpc_end2end_test_fixture *f, grpc_channel_args *server_args) {
  EnclaveCredentialsOptions creds =
      SelfNullCredentialsOptions().Add(PeerSgxLocalCredentialsOptions());

  EnclaveFullStackFixtureData *fixture_data =
      static_cast<EnclaveFullStackFixtureData *>(f->fixture_data);
  creds.peer_acl = fixture_data->identity_acl;

  InitServer(creds, f, server_args);
}

// Initializes the server in fixture |f| with |server_args| and bidirectional
// enclave null and SGX local credentials.
void InitServerEnclaveBidirectionalNullAndSgxLocalCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *server_args) {
  // Set the server's credentials options. The server supports bidirectional
  // authentication with null and SGX local credentials.
  InitServer(BidirectionalNullCredentialsOptions().Add(
                 BidirectionalSgxLocalCredentialsOptions()),
             f, server_args);
}

void TearDownSecureFullstack(grpc_end2end_test_fixture *f) {
  EnclaveFullStackFixtureData *fixture_data =
      static_cast<EnclaveFullStackFixtureData *>(f->fixture_data);
  delete fixture_data;
}

// All test configurations for the enclave gRPC stack.
static grpc_end2end_test_config configs[] = {
    // Bidirectional null-identity-based attestation.
    {"enclave_bidirectional_null_credentials",
     FEATURE_MASK_SUPPORTS_DELAYED_CONNECTION |
         FEATURE_MASK_SUPPORTS_CLIENT_CHANNEL |
         FEATURE_MASK_SUPPORTS_AUTHORITY_HEADER,
     /*overridden_call_host=*/nullptr, CreateFixtureSecureFullstack,
     InitClientEnclaveBidirectionalNullCredentials,
     InitServerEnclaveBidirectionalNullCredentials, TearDownSecureFullstack},

    // Bidirectional SGX local attestation.
    {"enclave_bidirectional_sgx_local_credentials",
     FEATURE_MASK_SUPPORTS_DELAYED_CONNECTION |
         FEATURE_MASK_SUPPORTS_CLIENT_CHANNEL |
         FEATURE_MASK_SUPPORTS_AUTHORITY_HEADER,
     /*overridden_call_host=*/nullptr, CreateFixtureSecureFullstack,
     InitClientEnclaveBidirectionalSgxLocalCredentials,
     InitServerEnclaveBidirectionalSgxLocalCredentials,
     TearDownSecureFullstack},

    // Client SGX local attestation, server null-identity-based attestation
    {"enclave_client_sgx_local_server_null_credentials",
     FEATURE_MASK_SUPPORTS_DELAYED_CONNECTION |
         FEATURE_MASK_SUPPORTS_CLIENT_CHANNEL |
         FEATURE_MASK_SUPPORTS_AUTHORITY_HEADER,
     /*overridden_call_host=*/nullptr, CreateFixtureSecureFullstack,
     InitClientEnclaveSelfSgxLocalPeerNullCredentials,
     InitServerEnclaveSelfNullPeerSgxLocalCredentials, TearDownSecureFullstack},

    // Bidirectional SGX local and null-identity-based attestation
    {"enclave_bidirectional_sgx_local_null_credentials",
     FEATURE_MASK_SUPPORTS_DELAYED_CONNECTION |
         FEATURE_MASK_SUPPORTS_CLIENT_CHANNEL |
         FEATURE_MASK_SUPPORTS_AUTHORITY_HEADER,
     /*overridden_call_host=*/nullptr, CreateFixtureSecureFullstack,
     InitClientEnclaveBidirectionalNullAndSgxLocalCredentials,
     InitServerEnclaveBidirectionalNullAndSgxLocalCredentials,
     TearDownSecureFullstack},

    // Client null-identity-based attestation, server SGX local attestation
    // with an ACL on the server.
    {"enclave_client_null_server_sgx_local_credentials_with_client_acl",
     FEATURE_MASK_SUPPORTS_DELAYED_CONNECTION |
         FEATURE_MASK_SUPPORTS_CLIENT_CHANNEL |
         FEATURE_MASK_SUPPORTS_AUTHORITY_HEADER,
     /*overridden_call_host=*/nullptr, CreateFixtureSecureFullstack,
     InitClientEnclaveSelfNullPeerSgxLocalWithAcl,
     InitServerEnclaveSelfSgxLocalPeerNullCredentials, TearDownSecureFullstack},

    // Client SGX local attestation, server null-identity-based attestation with
    // an ACL on the client.
    {"enclave_client_sgx_local_server_null_credentials_with_server_acl",
     FEATURE_MASK_SUPPORTS_DELAYED_CONNECTION |
         FEATURE_MASK_SUPPORTS_CLIENT_CHANNEL |
         FEATURE_MASK_SUPPORTS_AUTHORITY_HEADER,
     /*overridden_call_host=*/nullptr, CreateFixtureSecureFullstack,
     InitClientEnclaveSelfSgxLocalPeerNullCredentials,
     InitServerEnclaveSelfNullPeerSgxLocalWithAcl, TearDownSecureFullstack},
};

}  // namespace
}  // namespace asylo

int main(int argc, char **argv) {
  grpc_test_init(argc, argv);
  grpc_end2end_tests_pre_init();
  grpc_init();

  // Explicitly initialize all assertion authorities used in this test.
  std::vector<asylo::EnclaveAssertionAuthorityConfig> authority_configs = {
      asylo::GetNullAssertionAuthorityTestConfig(),
      asylo::GetSgxLocalAssertionAuthorityTestConfig(),
  };
  GPR_ASSERT(InitializeEnclaveAssertionAuthorities(authority_configs.cbegin(),
                                                   authority_configs.cend())
                 .ok());

  size_t i;
  for (i = 0; i < sizeof(asylo::configs) / sizeof(*asylo::configs); ++i) {
    GPR_ASSERT(asylo::configs[i].feature_mask != 0);
    grpc_end2end_tests(argc, argv, asylo::configs[i]);
  }

  grpc_shutdown();
  return 0;
}
