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

#include <string.h>

#include "asylo/enclave.pb.h"
#include "asylo/grpc/auth/core/enclave_credentials.h"
#include "asylo/grpc/auth/core/enclave_credentials_options.h"
#include "asylo/grpc/auth/enclave_credentials_options.h"
#include "asylo/grpc/auth/null_credentials_options.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "asylo/grpc/auth/util/bridge_cpp_to_c.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/init.h"
#include "asylo/identity/null_identity/null_identity_util.h"
#include "asylo/platform/core/trusted_global_state.h"
#include "include/grpc/impl/codegen/grpc_types.h"
#include "include/grpc/support/alloc.h"
#include "include/grpc/support/log.h"
#include "src/core/lib/gpr/host_port.h"
#include "test/core/end2end/end2end_tests.h"
#include "test/core/util/test_config.h"

namespace asylo {
namespace {

constexpr char kClientAdditionalAuthenticatedData[] = "EKEP client";
constexpr char kServerAdditionalAuthenticatedData[] = "EKEP server";
constexpr char kAddress[] = "[::1]";
constexpr char kLocalAttestationDomain[] = "gRPC Test Domain";

struct EnclaveFullStackFixtureData {
  // The address of the server.
  char *local_address;

  // True if the |local_address| has been updated to contain the server's final
  // port.
  bool port_set;
};

grpc_end2end_test_fixture CreateFixtureSecureFullstack(
    grpc_channel_args *client_args, grpc_channel_args *server_args) {
  grpc_end2end_test_fixture f;

  EnclaveFullStackFixtureData *fixture_data =
      static_cast<EnclaveFullStackFixtureData *>(
          gpr_zalloc(sizeof(*fixture_data)));

  // A port of indicates that gRPC should auto-select a port for use. This
  // address is updated with the final port after server initialization.
  gpr_join_host_port(&fixture_data->local_address, kAddress, 0);
  f.fixture_data = fixture_data;

  // Create a completion queue for the server.
  f.cq = grpc_completion_queue_create_for_next(nullptr);
  f.shutdown_cq = grpc_completion_queue_create_for_pluck(nullptr);

  // The |client| and |server| are configured later in the test.
  f.server = nullptr;
  f.client = nullptr;

  return f;
}

// Uses |options| to construct gRPC enclave channel credentials,
// and sets |credentials| to point to the resulting credentials object.
void InitClientEnclaveCredentials(const EnclaveCredentialsOptions &options,
                                  grpc_channel_credentials **credentials) {
  grpc_enclave_credentials_options c_options;
  grpc_enclave_credentials_options_init(&c_options);
  CopyEnclaveCredentialsOptions(options, &c_options);

  *credentials = grpc_enclave_channel_credentials_create(&c_options);
}

// Initializes the channel in fixture |f| using |client_args| and |options|.
void InitClientChannel(EnclaveCredentialsOptions options,
                       grpc_end2end_test_fixture *f,
                       grpc_channel_args *client_args) {
  // The client's AAD is just a fixed string in this test.
  options.additional_authenticated_data = kClientAdditionalAuthenticatedData;

  // Create enclave gRPC channel credentials.
  grpc_channel_credentials *creds = nullptr;
  InitClientEnclaveCredentials(options, &creds);
  GPR_ASSERT(creds != nullptr);

  EnclaveFullStackFixtureData *fixture_data =
      static_cast<EnclaveFullStackFixtureData *>(f->fixture_data);
  GPR_ASSERT(fixture_data->port_set);
  f->client = grpc_secure_channel_create(creds, fixture_data->local_address,
                                         client_args, /*reserved=*/nullptr);
  GPR_ASSERT(f->client != nullptr);
  grpc_channel_credentials_release(creds);
}

// Initializes the client in fixture |f| with |server_args| and bidirectional
// enclave null credentials.
void InitClientEnclaveBidirectionalNullCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *client_args) {
  // Set the client's credentials options. The client supports bidirectional
  // authentication based on null assertions.
  InitClientChannel(BidirectionalNullCredentialsOptions(), f, client_args);
}

// Initializes the client in fixture |f| with |server_args| and bidirectional
// enclave SGX local credentials.
void InitClientEnclaveBidirectionalSgxLocalCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *client_args) {
  // Set the client's credentials options. The client supports bidirectional
  // authentication based on SGX local attestation.
  InitClientChannel(BidirectionalSgxLocalCredentialsOptions(), f, client_args);
}

// Initializes the client in fixture |f| with |server_args| and channel
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

// Initializes the client in fixture |f| with |server_args| and bidirectional
// enclave SGX local credentials and null credentials.
void InitClientEnclaveBidirectionalNullAndSgxLocalCredentials(
    grpc_end2end_test_fixture *f, grpc_channel_args *client_args) {
  // Set the client's credentials options. The client supports bidirectional
  // authentication based on SGX local attestation or no authentication.
  InitClientChannel(BidirectionalNullCredentialsOptions().Add(
                        BidirectionalSgxLocalCredentialsOptions()),
                    f, client_args);
}

// Uses |options| to construct gRPC enclave server credentials,
// and sets |credentials| to point to the resulting credentials object.
void InitServerEnclaveCredentials(const EnclaveCredentialsOptions &options,
                                  grpc_server_credentials **credentials) {
  grpc_enclave_credentials_options c_options;
  grpc_enclave_credentials_options_init(&c_options);
  CopyEnclaveCredentialsOptions(options, &c_options);

  // Create enclave gRPC server credentials.
  *credentials = grpc_enclave_server_credentials_create(&c_options);
}

// Initializes the server in fixture |f| using |server_args| and |options|.
void InitServer(EnclaveCredentialsOptions options, grpc_end2end_test_fixture *f,
                grpc_channel_args *server_args) {
  // The server's AAD is just a fixed string in this test.
  options.additional_authenticated_data = kServerAdditionalAuthenticatedData;

  // Create enclave gRPC server credentials.
  grpc_server_credentials *creds = nullptr;
  InitServerEnclaveCredentials(options, &creds);
  GPR_ASSERT(creds != nullptr);

  EnclaveFullStackFixtureData *fixture_data =
      static_cast<EnclaveFullStackFixtureData *>(f->fixture_data);
  f->server = grpc_server_create(server_args, /*reserved=*/nullptr);
  grpc_server_register_completion_queue(f->server, f->cq, /*reserved=*/nullptr);

  // Bind the server to the temporary address and update the address with the
  // auto-selected port chosen by the system.
  int port = grpc_server_add_secure_http2_port(
      f->server, fixture_data->local_address, creds);
  GPR_ASSERT(port != 0);
  gpr_free(fixture_data->local_address);
  gpr_join_host_port(&fixture_data->local_address, kAddress, port);
  fixture_data->port_set = true;

  grpc_server_credentials_release(creds);
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
  gpr_free(fixture_data->local_address);
  gpr_free(fixture_data);
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
};

}  // namespace
}  // namespace asylo

int main(int argc, char **argv) {
  grpc_test_init(argc, argv);
  grpc_end2end_tests_pre_init();
  grpc_init();

  // Set the attestation domain in the global EnclaveConfig.
  asylo::EnclaveConfig enclave_config;
  enclave_config.mutable_host_config()->set_local_attestation_domain(
      asylo::kLocalAttestationDomain);
  asylo::SetEnclaveConfig(enclave_config);

  // Initialize all enclave assertion authorities. No configs are currently
  // needed for either the null or SGX local null assertion authorities.
  // Consequently, no configs are provided and this call will just initialize
  // each authority with an empty config string.
  std::vector<asylo::EnclaveAssertionAuthorityConfig> authority_configs;
  GPR_ASSERT(asylo::InitializeEnclaveAssertionAuthorities(
                 authority_configs.begin(), authority_configs.end())
                 .ok());

  size_t i;
  for (i = 0; i < sizeof(asylo::configs) / sizeof(*asylo::configs); ++i) {
    GPR_ASSERT(asylo::configs[i].feature_mask != 0);
    grpc_end2end_tests(argc, argv, asylo::configs[i]);
  }

  grpc_shutdown();
  return 0;
}
