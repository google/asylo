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

#include "asylo/grpc/auth/core/assertion_description.h"
#include "asylo/grpc/auth/core/enclave_credentials.h"
#include "asylo/grpc/auth/core/enclave_credentials_options.h"
#include "asylo/grpc/auth/test/end2end_test_util.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/init.h"
#include "include/grpc/support/alloc.h"
#include "include/grpc/support/log.h"
#include "src/core/lib/gpr/host_port.h"
#include "test/core/end2end/end2end_tests.h"
#include "test/core/util/port.h"
#include "test/core/util/test_config.h"

const char kClientAdditionalAuthenticatedData[] = "EKEP client";
const char kServerAdditionalAuthenticatedData[] = "EKEP server";

typedef struct enclave_fullstack_fixture_data {
  char *local_address;
} enclave_fullstack_fixture_data;

static grpc_end2end_test_fixture chttp2_create_fixture_secure_fullstack(
    grpc_channel_args *client_args,
    grpc_channel_args *server_args) {
  grpc_end2end_test_fixture f;
  memset(&f, 0, sizeof(f));

  // Get a local port for the server.
  int port = grpc_pick_unused_port_or_die();
  enclave_fullstack_fixture_data *fixture_data =
      static_cast<enclave_fullstack_fixture_data *>(
          gpr_malloc(sizeof(*fixture_data)));

  // This call allocs a string in |fixture_data->local_address| that must later
  // be de-allocated.
  gpr_join_host_port(&fixture_data->local_address, "localhost", port);
  f.fixture_data = fixture_data;

  // Create a completion queue for the server.
  f.cq = grpc_completion_queue_create_for_next(NULL);
  f.shutdown_cq = grpc_completion_queue_create_for_pluck(NULL);
  return f;
}

static void chttp2_init_client_channel(grpc_end2end_test_fixture *f,
                                       grpc_channel_args *client_args,
                                       grpc_channel_credentials *creds) {
  enclave_fullstack_fixture_data *fixture_data =
      static_cast<enclave_fullstack_fixture_data *>(f->fixture_data);
  f->client = grpc_secure_channel_create(creds, fixture_data->local_address,
                                         client_args, /*reserved=*/NULL);
  GPR_ASSERT(f->client != NULL);
  grpc_channel_credentials_release(creds);
}

static void chttp2_init_client_enclave_secure_fullstack(
    grpc_end2end_test_fixture *f,
    grpc_channel_args *client_args) {
  // Create enclave channel credentials.
  grpc_enclave_credentials_options options;
  grpc_enclave_credentials_options_init(&options);

  // The client's AAD is just a fixed string in this test.
  safe_string_assign(&options.additional_authenticated_data,
                     strlen(kClientAdditionalAuthenticatedData),
                     kClientAdditionalAuthenticatedData);

  // The client offers a null assertion.
  assertion_description_array_init(/*count=*/1, &options.self_assertions);
  set_null_assertion(&options.self_assertions.descriptions[0]);

  // The client only accepts null assertions.
  assertion_description_array_init(/*count=*/1,
                                   &options.accepted_peer_assertions);
  set_null_assertion(&options.accepted_peer_assertions.descriptions[0]);

  grpc_channel_credentials *creds =
      grpc_enclave_channel_credentials_create(&options);

  // Initialize client.
  chttp2_init_client_channel(f, client_args, creds);
}

static void chttp2_init_server(grpc_end2end_test_fixture *f,
                               grpc_channel_args *server_args,
                               grpc_server_credentials *creds) {
  enclave_fullstack_fixture_data *fixture_data =
      static_cast<enclave_fullstack_fixture_data *>(f->fixture_data);
  f->server = grpc_server_create(server_args, /*reserved=*/NULL);
  grpc_server_register_completion_queue(f->server, f->cq, /*reserved=*/NULL);
  GPR_ASSERT(grpc_server_add_secure_http2_port(f->server,
                                               fixture_data->local_address,
                                               creds));
  grpc_server_credentials_release(creds);
  grpc_server_start(f->server);
}

static void chttp2_init_server_enclave_secure_fullstack(
    grpc_end2end_test_fixture *f,
    grpc_channel_args *server_args) {
  // Create enclave server credentials.
  grpc_enclave_credentials_options options;
  grpc_enclave_credentials_options_init(&options);

  // The server's AAD is just a fixed string in this test.
  safe_string_assign(&options.additional_authenticated_data,
                     strlen(kServerAdditionalAuthenticatedData),
                     kServerAdditionalAuthenticatedData);

  // The server offers a null assertion.
  assertion_description_array_init(/*count=*/1, &options.self_assertions);
  set_null_assertion(&options.self_assertions.descriptions[0]);

  // The server only accepts null assertions.
  assertion_description_array_init(/*count=*/1,
                                   &options.accepted_peer_assertions);
  set_null_assertion(&options.accepted_peer_assertions.descriptions[0]);

  grpc_server_credentials *creds =
      grpc_enclave_server_credentials_create(&options);

  // Initialize server.
  chttp2_init_server(f, server_args, creds);
}

static void chttp2_tear_down_secure_fullstack(grpc_end2end_test_fixture *f) {
  enclave_fullstack_fixture_data *fixture_data =
      static_cast<enclave_fullstack_fixture_data *>(f->fixture_data);
  gpr_free(fixture_data->local_address);
  gpr_free(fixture_data);
}

// All test configurations for the enclave gRPC stack.
static grpc_end2end_test_config configs[] = {
  {"enclave_secure_fullstack",
   FEATURE_MASK_SUPPORTS_DELAYED_CONNECTION |
       FEATURE_MASK_SUPPORTS_CLIENT_CHANNEL |
       FEATURE_MASK_SUPPORTS_AUTHORITY_HEADER,
   /*overridden_call_host=*/ nullptr,
   chttp2_create_fixture_secure_fullstack,
   chttp2_init_client_enclave_secure_fullstack,
   chttp2_init_server_enclave_secure_fullstack,
   chttp2_tear_down_secure_fullstack},
};

int main(int argc, char **argv) {
  grpc_test_init(argc, argv);
  grpc_end2end_tests_pre_init();
  grpc_init();

  // Initialize all enclave assertion authorities. No configs are needed for
  // null assertion authorities. Consequently, this call will just initialize
  // each authority with an empty config string.
  std::vector<asylo::EnclaveAssertionAuthorityConfig> authority_configs;
  GPR_ASSERT(asylo::InitializeEnclaveAssertionAuthorities(
                 authority_configs.begin(), authority_configs.end())
                 .ok());

  size_t i;
  for (i = 0; i < sizeof(configs) / sizeof(*configs); ++i) {
    GPR_ASSERT(configs[i].feature_mask != 0);
    grpc_end2end_tests(argc, argv, configs[i]);
  }

  grpc_shutdown();
  return 0;
}
