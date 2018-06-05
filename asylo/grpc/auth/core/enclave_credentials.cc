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

#include "asylo/grpc/auth/core/enclave_credentials.h"

#include <string.h>

#include "asylo/grpc/auth/core/assertion_description.h"
#include "asylo/grpc/auth/core/enclave_security_connector.h"
#include "asylo/grpc/auth/util/safe_string.h"
#include "include/grpc/support/alloc.h"
#include "include/grpc/support/log.h"
#include "src/core/lib/channel/channel_args.h"
#include "src/core/lib/security/credentials/credentials.h"

/* Frees any memory allocated by this channel credentials object.
 * Note that this function does not destroy the credentials object itself. */
static void enclave_channel_credentials_destruct(
    grpc_channel_credentials *creds) {
  grpc_enclave_channel_credentials *credentials =
      reinterpret_cast<grpc_enclave_channel_credentials *>(creds);
  safe_string_free(&credentials->additional_authenticated_data);
  assertion_description_array_free(&credentials->self_assertions);
  assertion_description_array_free(&credentials->accepted_peer_assertions);
}

/* Frees any memory allocated by this server credentials object.
 * Note that this function does not destroy the credentials object itself. */
static void enclave_server_credentials_destruct(
    grpc_server_credentials *creds) {
  grpc_enclave_server_credentials *credentials =
      reinterpret_cast<grpc_enclave_server_credentials *>(creds);
  safe_string_free(&credentials->additional_authenticated_data);
  assertion_description_array_free(&credentials->self_assertions);
  assertion_description_array_free(&credentials->accepted_peer_assertions);
}

/* Creates an enclave channel security connector. */
static grpc_security_status enclave_channel_security_connector_create(
    grpc_channel_credentials *channel_creds, grpc_call_credentials *call_creds,
    const char *target, const grpc_channel_args *args,
    grpc_channel_security_connector **security_connector,
    grpc_channel_args **new_args) {
  *security_connector = grpc_enclave_channel_security_connector_create(
      channel_creds, call_creds, target);
  return GRPC_SECURITY_OK;
}

/* Creates an enclave server security connector. */
static grpc_security_status enclave_server_security_connector_create(
    grpc_server_credentials *server_creds,
    grpc_server_security_connector **security_connector) {
  *security_connector =
      grpc_enclave_server_security_connector_create(server_creds);
  return GRPC_SECURITY_OK;
}

static grpc_channel_credentials_vtable enclave_credentials_vtable = {
    /* Channel credentials destructor. */
    enclave_channel_credentials_destruct,
    /* Channel security connector constructor. */
    enclave_channel_security_connector_create,
    /* No implementation provided for duplicate_without_call_credentials(...).
     */
    nullptr};

static grpc_server_credentials_vtable enclave_server_credentials_vtable = {
    /* Server credentials destructor. */
    enclave_server_credentials_destruct,
    /* Server security connector constructor. */
    enclave_server_security_connector_create};

grpc_channel_credentials *grpc_enclave_channel_credentials_create(
    const grpc_enclave_credentials_options *options) {
  grpc_enclave_channel_credentials *credentials =
      static_cast<grpc_enclave_channel_credentials *>(
          gpr_malloc(sizeof(*credentials)));

  // Initialize all members.
  safe_string_init(&credentials->additional_authenticated_data);
  assertion_description_array_init(/*count=*/0, &credentials->self_assertions);
  assertion_description_array_init(/*count=*/0,
                                   &credentials->accepted_peer_assertions);

  // Copy parameters.
  safe_string_copy(/*dest=*/&credentials->additional_authenticated_data,
                   /*src=*/&options->additional_authenticated_data);
  assertion_description_array_copy(/*src=*/&options->self_assertions,
                                   /*dest=*/&credentials->self_assertions);
  assertion_description_array_copy(
      /*src=*/&options->accepted_peer_assertions,
      /*dest=*/&credentials->accepted_peer_assertions);

  // Initialize the base credentials object
  credentials->base.type = GRPC_CREDENTIALS_TYPE_ENCLAVE;
  credentials->base.vtable = &enclave_credentials_vtable;
  gpr_ref_init(&credentials->base.refcount, 1);

  return &credentials->base;
}

grpc_server_credentials *grpc_enclave_server_credentials_create(
    const grpc_enclave_credentials_options *options) {
  grpc_enclave_server_credentials *credentials =
      static_cast<grpc_enclave_server_credentials *>(
          gpr_malloc(sizeof(*credentials)));

  // Initialize all members.
  safe_string_init(&credentials->additional_authenticated_data);
  assertion_description_array_init(/*count=*/0, &credentials->self_assertions);
  assertion_description_array_init(/*count=*/0,
                                   &credentials->accepted_peer_assertions);

  // Copy parameters.
  safe_string_copy(/*dest=*/&credentials->additional_authenticated_data,
                   /*src=*/&options->additional_authenticated_data);
  assertion_description_array_copy(/*src=*/&options->self_assertions,
                                   /*dest=*/&credentials->self_assertions);
  assertion_description_array_copy(
      /*src=*/&options->accepted_peer_assertions,
      /*dest=*/&credentials->accepted_peer_assertions);

  // Initialize the base credentials object.
  credentials->base.type = GRPC_CREDENTIALS_TYPE_ENCLAVE;
  credentials->base.vtable = &enclave_server_credentials_vtable;
  gpr_ref_init(&credentials->base.refcount, 1);
  memset(&credentials->base.processor, 0, sizeof(credentials->base.processor));

  return &credentials->base;
}
