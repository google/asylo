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

#include "asylo/grpc/auth/core/enclave_security_connector.h"

#include <stdbool.h>
#include <string.h>

#include "asylo/grpc/auth/core/assertion_description.h"
#include "asylo/grpc/auth/core/enclave_credentials.h"
#include "asylo/grpc/auth/core/enclave_grpc_security_constants.h"
#include "asylo/grpc/auth/core/enclave_transport_security.h"
#include "asylo/grpc/auth/util/safe_string.h"
#include "include/grpc/support/alloc.h"
#include "include/grpc/support/log.h"
#include "include/grpc/support/string_util.h"
#include "src/core/lib/security/context/security_context.h"
#include "src/core/lib/security/credentials/credentials.h"
#include "src/core/lib/security/transport/security_handshaker.h"
#include "src/core/lib/surface/api_trace.h"
#include "src/core/tsi/transport_security.h"

/* -- Enclave security connectors. -- */

typedef struct {
  grpc_channel_security_connector base;

  /* The address of the server as a null-terminated std::string. */
  char *target;
} grpc_enclave_channel_security_connector;

typedef struct {
  grpc_server_security_connector base;
} grpc_enclave_server_security_connector;

/* -- Enclave security connector implementation. -- */

/* Frees all memory allocated by the channel security connector and destroys
 * the security connector itself. */
static void enclave_channel_security_connector_destroy(
    grpc_security_connector *sc) {
  grpc_enclave_channel_security_connector *security_connector =
      reinterpret_cast<grpc_enclave_channel_security_connector *>(sc);
  grpc_channel_credentials_unref(security_connector->base.channel_creds);
  grpc_call_credentials_unref(security_connector->base.request_metadata_creds);
  if (security_connector->target != nullptr) {
    gpr_free(security_connector->target);
  }
  gpr_free(sc);
}

/* Frees all memory allocated by the server security connector and destroys
 * the security connector itself. */
static void enclave_server_security_connector_destroy(
    grpc_security_connector *sc) {
  grpc_enclave_server_security_connector *security_connector =
      reinterpret_cast<grpc_enclave_server_security_connector *>(sc);
  grpc_server_credentials_unref(security_connector->base.server_creds);
  gpr_free(sc);
}

grpc_security_status grpc_enclave_auth_context_from_tsi_peer(
    const tsi_peer *peer, grpc_auth_context **auth_context) {
  // Authenticated peers should have the following properties:
  //   * TSI_CERTIFICATE_TYPE_PEER_PROPERTY
  //   * TSI_ENCLAVE_IDENTITIES_PROTO_PEER_PROPERTY
  //   * TSI_ENCLAVE_RECORD_PROTOCOL_PEER_PROPERTY
  // They are translated into the following authentication context properties:
  //   * GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME
  //   * GRPC_ENCLAVE_IDENTITIES_PROTO_PROPERTY_NAME
  //   * GRPC_ENCLAVE_RECORD_PROTOCOL_PROPERTY_NAME
  const tsi_peer_property *certificate_type_property =
      tsi_peer_get_property_by_name(peer, TSI_CERTIFICATE_TYPE_PEER_PROPERTY);
  // Check if all expected properties are present.
  if (certificate_type_property == nullptr) {
    gpr_log(GPR_ERROR, "Missing certificate type peer property");
    return GRPC_SECURITY_ERROR;
  }
  if (strncmp(TSI_ENCLAVE_CERTIFICATE_TYPE,
              certificate_type_property->value.data,
              certificate_type_property->value.length) != 0) {
    gpr_log(GPR_ERROR, "Invalid certificate type peer property");
    return GRPC_SECURITY_ERROR;
  }

  const tsi_peer_property *identity_property = tsi_peer_get_property_by_name(
      peer, TSI_ENCLAVE_IDENTITIES_PROTO_PEER_PROPERTY);
  if (identity_property == nullptr) {
    gpr_log(GPR_ERROR, "Missing identity proto peer property");
    return GRPC_SECURITY_ERROR;
  }

  const tsi_peer_property *record_protocol_property =
      tsi_peer_get_property_by_name(peer,
                                    TSI_ENCLAVE_RECORD_PROTOCOL_PEER_PROPERTY);
  if (record_protocol_property == nullptr) {
    gpr_log(GPR_ERROR, "Missing record protocol peer property");
    return GRPC_SECURITY_ERROR;
  }

  // Create a new authentication context and set the properties.
  *auth_context = grpc_auth_context_create(/*chained=*/nullptr);
  grpc_auth_context_add_cstring_property(
      *auth_context, GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME,
      GRPC_ENCLAVE_TRANSPORT_SECURITY_TYPE);
  grpc_auth_context_add_property(
      *auth_context, GRPC_ENCLAVE_IDENTITIES_PROTO_PROPERTY_NAME,
      identity_property->value.data, identity_property->value.length);
  grpc_auth_context_add_property(*auth_context,
                                 GRPC_ENCLAVE_RECORD_PROTOCOL_PROPERTY_NAME,
                                 record_protocol_property->value.data,
                                 record_protocol_property->value.length);
  // The EnclaveIdentities proto is the identity in the authentication context.
  if (!grpc_auth_context_set_peer_identity_property_name(
          *auth_context, GRPC_ENCLAVE_IDENTITIES_PROTO_PROPERTY_NAME)) {
    gpr_log(GPR_ERROR, "Error setting peer identity property name");
    return GRPC_SECURITY_ERROR;
  }


  return GRPC_SECURITY_OK;
}

static void enclave_security_connector_check_peer(
    grpc_security_connector *sc, tsi_peer peer,
    grpc_auth_context **auth_context, grpc_closure *on_peer_checked) {
  grpc_error *error = GRPC_ERROR_NONE;
  grpc_security_status status =
      grpc_enclave_auth_context_from_tsi_peer(&peer, auth_context);
  tsi_peer_destruct(&peer);
  if (status != GRPC_SECURITY_OK) {
    error = GRPC_ERROR_CREATE_FROM_STATIC_STRING(
        "Failed to get enclave auth context from TSI peer");
  }

  GRPC_CLOSURE_SCHED(on_peer_checked, error);
}

static bool enclave_channel_check_call_host(grpc_channel_security_connector *sc,
                                            const char *host,
                                            grpc_auth_context *auth_context,
                                            grpc_closure *on_call_host_checked,
                                            grpc_error **error) {
  return true;
}

static void enclave_channel_cancel_check_call_host(
    grpc_channel_security_connector *sc, grpc_closure *on_call_host_checked,
    grpc_error *error) {
  GRPC_ERROR_UNREF(error);
}

static int enclave_channel_security_connector_cmp(
    grpc_security_connector *sc1, grpc_security_connector *sc2) {
  return 1;
}

static int enclave_server_security_connector_cmp(grpc_security_connector *sc1,
                                                 grpc_security_connector *sc2) {
  return 1;
}

static void enclave_channel_security_connector_add_handshaker(
    grpc_channel_security_connector *security_connector,
    grpc_handshake_manager *handshake_mgr) {
  tsi_handshaker *tsi_handshaker = nullptr;
  grpc_enclave_channel_credentials *channel_creds =
      reinterpret_cast<grpc_enclave_channel_credentials *>(
          security_connector->channel_creds);
  tsi_result result = tsi_enclave_handshaker_create(
      /*is_client=*/true, &channel_creds->self_assertions,
      &channel_creds->accepted_peer_assertions,
      &channel_creds->additional_authenticated_data, &tsi_handshaker);
  if (result != TSI_OK) {
    gpr_log(GPR_ERROR, "Enclave handshaker creation failed with error %s.",
            tsi_result_to_string(result));
    return;
  }

  grpc_handshake_manager_add(handshake_mgr,
                             grpc_security_handshaker_create(
                                 tsi_handshaker, &security_connector->base));
}

static void enclave_server_security_connector_add_handshakers(
    grpc_server_security_connector *security_connector,
    grpc_handshake_manager *handshake_mgr) {
  tsi_handshaker *tsi_handshaker = nullptr;
  grpc_enclave_server_credentials *server_creds =
      reinterpret_cast<grpc_enclave_server_credentials *>(
          security_connector->server_creds);
  tsi_result result = tsi_enclave_handshaker_create(
      /*is_client=*/false, &server_creds->self_assertions,
      &server_creds->accepted_peer_assertions,
      &server_creds->additional_authenticated_data, &tsi_handshaker);
  if (result != TSI_OK) {
    gpr_log(GPR_ERROR, "Enclave handshaker creation failed with error %s.",
            tsi_result_to_string(result));
    return;
  }

  grpc_handshake_manager_add(handshake_mgr,
                             grpc_security_handshaker_create(
                                 tsi_handshaker, &security_connector->base));
}

static grpc_security_connector_vtable
    enclave_channel_security_connector_vtable = {
        /* Enclave channel security connector destructor. */
        enclave_channel_security_connector_destroy,
        /* Populates a tsi_peer object with information about the peer (server).
         */
        enclave_security_connector_check_peer,
        /* Compares this enclave channel security connector with another. */
        enclave_channel_security_connector_cmp};

static grpc_security_connector_vtable enclave_server_security_connector_vtable =
    {
        /* Enclave server security connector destructor. */
        enclave_server_security_connector_destroy,
        /* Populates a tsi_peer object with information about the peer (client).
         */
        enclave_security_connector_check_peer,
        /* Compares this enclave server security connector with another. */
        enclave_server_security_connector_cmp};

/* -- Enclave security connector creation functions -- */

grpc_channel_security_connector *grpc_enclave_channel_security_connector_create(
    grpc_channel_credentials *channel_credentials,
    grpc_call_credentials *request_metadata_creds, const char *target) {
  GRPC_API_TRACE(
      "grpc_enclave_channel_security_connector_create("
      "grpc_channel_credentials=%p, grpc_call_credentials=%p, target=%s)",
      3, (channel_credentials, request_metadata_creds, target));
  grpc_enclave_channel_security_connector *security_connector =
      static_cast<grpc_enclave_channel_security_connector *>(
          gpr_malloc(sizeof(*security_connector)));

  // Initialize all members.
  gpr_ref_init(&security_connector->base.base.refcount, 1);

  // Copy parameters.
  if (target != nullptr) {
    security_connector->target = gpr_strdup(target);
  }

  // Initialize the base channel security connector object.
  grpc_channel_security_connector &base = security_connector->base;
  base.base.vtable = &enclave_channel_security_connector_vtable;
  base.channel_creds = grpc_channel_credentials_ref(channel_credentials);
  base.request_metadata_creds =
      grpc_call_credentials_ref(request_metadata_creds);
  base.check_call_host = enclave_channel_check_call_host;
  base.cancel_check_call_host = enclave_channel_cancel_check_call_host;
  base.add_handshakers = enclave_channel_security_connector_add_handshaker;

  return &security_connector->base;
}

grpc_server_security_connector *grpc_enclave_server_security_connector_create(
    grpc_server_credentials *server_credentials) {
  GRPC_API_TRACE(
      "grpc_enclave_server_security_connector_create("
      "grpc_server_credentials=%p)",
      1, (server_credentials));
  grpc_enclave_server_security_connector *security_connector =
      static_cast<grpc_enclave_server_security_connector *>(
          gpr_malloc(sizeof(*security_connector)));

  // Initialize all members.
  gpr_ref_init(&security_connector->base.base.refcount, 1);

  // Initialize the base server security connector object.
  grpc_server_security_connector &base = security_connector->base;
  base.base.vtable = &enclave_server_security_connector_vtable;
  base.server_creds = grpc_server_credentials_ref(server_credentials);
  base.add_handshakers = enclave_server_security_connector_add_handshakers;

  return &security_connector->base;
}
