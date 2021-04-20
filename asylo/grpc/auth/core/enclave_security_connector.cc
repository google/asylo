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

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/util/logging.h"
#include "asylo/grpc/auth/core/enclave_credentials.h"
#include "asylo/grpc/auth/core/enclave_grpc_security_constants.h"
#include "asylo/grpc/auth/core/enclave_transport_security.h"
#include "include/grpc/support/alloc.h"
#include "include/grpc/support/log.h"
#include "include/grpc/support/string_util.h"
#include "src/core/lib/gprpp/ref_counted_ptr.h"
#include "src/core/lib/iomgr/pollset.h"
#include "src/core/lib/security/context/security_context.h"
#include "src/core/lib/security/credentials/credentials.h"
#include "src/core/lib/security/transport/security_handshaker.h"
#include "src/core/lib/surface/api_trace.h"
#include "src/core/tsi/transport_security.h"
#include "src/core/tsi/transport_security_interface.h"

namespace {

grpc_security_status grpc_enclave_auth_context_from_tsi_peer(
    const tsi_peer *peer,
    grpc_core::RefCountedPtr<grpc_auth_context> *auth_context) {
  // Authenticated peers should have the following properties:
  //   * TSI_CERTIFICATE_TYPE_PEER_PROPERTY
  //   * TSI_SECURITY_LEVEL_PEER_PROPERTY
  //   * TSI_ENCLAVE_IDENTITIES_PROTO_PEER_PROPERTY
  //   * TSI_ENCLAVE_RECORD_PROTOCOL_PEER_PROPERTY
  // They are translated into the following authentication context properties:
  //   * GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME
  //   * GRPC_TRANSPORT_SECURITY_LEVEL_PROPERTY_NAME
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
  const tsi_peer_property *security_level_property =
      tsi_peer_get_property_by_name(peer, TSI_SECURITY_LEVEL_PEER_PROPERTY);
  if (security_level_property == nullptr) {
    gpr_log(GPR_ERROR, "Missing security level property.");
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
  *auth_context =
      grpc_core::MakeRefCounted<grpc_auth_context>(/*chained=*/nullptr);
  grpc_auth_context_add_cstring_property(
      auth_context->get(), GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME,
      GRPC_ENCLAVE_TRANSPORT_SECURITY_TYPE);
  grpc_auth_context_add_property(
      auth_context->get(), GRPC_ENCLAVE_IDENTITIES_PROTO_PROPERTY_NAME,
      identity_property->value.data, identity_property->value.length);
  grpc_auth_context_add_property(auth_context->get(),
                                 GRPC_ENCLAVE_RECORD_PROTOCOL_PROPERTY_NAME,
                                 record_protocol_property->value.data,
                                 record_protocol_property->value.length);
  grpc_auth_context_add_property(auth_context->get(),
                                 GRPC_TRANSPORT_SECURITY_LEVEL_PROPERTY_NAME,
                                 security_level_property->value.data,
                                 security_level_property->value.length);
  // The EnclaveIdentities proto is the identity in the authentication context.
  if (!grpc_auth_context_set_peer_identity_property_name(
          auth_context->get(), GRPC_ENCLAVE_IDENTITIES_PROTO_PROPERTY_NAME)) {
    gpr_log(GPR_ERROR, "Error setting peer identity property name");
    return GRPC_SECURITY_ERROR;
  }


  return GRPC_SECURITY_OK;
}

void enclave_security_connector_check_peer(
    grpc_security_connector *sc, tsi_peer peer,
    grpc_core::RefCountedPtr<grpc_auth_context> *auth_context,
    grpc_closure *on_peer_checked) {
  grpc_error *error = GRPC_ERROR_NONE;
  grpc_security_status status =
      grpc_enclave_auth_context_from_tsi_peer(&peer, auth_context);
  tsi_peer_destruct(&peer);
  if (status != GRPC_SECURITY_OK) {
    error = GRPC_ERROR_CREATE_FROM_STATIC_STRING(
        "Failed to get enclave auth context from TSI peer");
  }

  grpc_core::ExecCtx::Run(DEBUG_LOCATION, on_peer_checked, error);
}

/* -- Enclave security connector implementation. -- */

class grpc_enclave_channel_security_connector final
    : public grpc_channel_security_connector {
 public:
  grpc_enclave_channel_security_connector(
      grpc_core::RefCountedPtr<grpc_channel_credentials> channel_credentials,
      grpc_core::RefCountedPtr<grpc_call_credentials> request_metadata_creds,
      const char *target)
      : grpc_channel_security_connector(/*url_scheme=*/nullptr,
                                        std::move(channel_credentials),
                                        std::move(request_metadata_creds)),
        target_(gpr_strdup(target)) {}

  ~grpc_enclave_channel_security_connector() override {
    gpr_free(target_);
  }

  void check_peer(tsi_peer peer, grpc_endpoint *ep,
                  grpc_core::RefCountedPtr<grpc_auth_context> *auth_context,
                  grpc_closure *on_peer_checked) override {
    enclave_security_connector_check_peer(this, peer, auth_context,
                                          on_peer_checked);
  }


  bool check_call_host(absl::string_view host, grpc_auth_context *auth_context,
                       grpc_closure *on_call_host_checked,
                       grpc_error **error) override {
    return true;
  }

  void cancel_check_call_host(
      grpc_closure *on_call_host_checked,
      grpc_error *error) override {

    GRPC_ERROR_UNREF(error);
  }

  int cmp(const grpc_security_connector * /*other*/) const override {
    return 1;
  }

  void add_handshakers(
      const grpc_channel_args* args,
      grpc_pollset_set *interested_parties,
      grpc_handshake_manager *handshake_mgr) override {
    tsi_handshaker *tsi_handshaker = nullptr;
    grpc_enclave_channel_credentials *channel_creds =
        CHECK_NOTNULL(dynamic_cast<grpc_enclave_channel_credentials *>(
            this->mutable_channel_creds()));
    tsi_result result = tsi_enclave_handshaker_create(
        /*is_client=*/true, absl::MakeSpan(channel_creds->self_assertions),
        absl::MakeSpan(channel_creds->accepted_peer_assertions),
        channel_creds->additional_authenticated_data, channel_creds->peer_acl,
        &tsi_handshaker);
    if (result != TSI_OK) {
      gpr_log(GPR_ERROR, "Enclave handshaker creation failed with error %s.",
              tsi_result_to_string(result));
      return;
    }

    grpc_handshake_manager_add(
        handshake_mgr, grpc_security_handshaker_create(tsi_handshaker, this,
                                                       args));
  }

 private:
  // The address of the server as a null-terminated string.
  char *target_;
};

class grpc_enclave_server_security_connector final
    : public grpc_server_security_connector {
 public:
  explicit grpc_enclave_server_security_connector(
      grpc_core::RefCountedPtr<grpc_server_credentials> server_credentials)
      : grpc_server_security_connector(/*url_scheme=*/nullptr,
                                       std::move(server_credentials)) {}
  ~grpc_enclave_server_security_connector() override = default;

  void check_peer(tsi_peer peer, grpc_endpoint *ep,
                  grpc_core::RefCountedPtr<grpc_auth_context> *auth_context,
                  grpc_closure *on_peer_checked) override {
    enclave_security_connector_check_peer(this, peer, auth_context,
                                          on_peer_checked);
  }


  int cmp(const grpc_security_connector * /*other*/) const override {
    return 1;
  }

  void add_handshakers(
      const grpc_channel_args* args,
      grpc_pollset_set *interested_parties,
      grpc_handshake_manager *handshake_mgr) override {
    tsi_handshaker *tsi_handshaker = nullptr;
    grpc_enclave_server_credentials *server_creds =
        CHECK_NOTNULL(dynamic_cast<grpc_enclave_server_credentials *>(
            this->mutable_server_creds()));
    tsi_result result = tsi_enclave_handshaker_create(
        /*is_client=*/false, absl::MakeSpan(server_creds->self_assertions),
        absl::MakeSpan(server_creds->accepted_peer_assertions),
        server_creds->additional_authenticated_data, server_creds->peer_acl,
        &tsi_handshaker);
    if (result != TSI_OK) {
      gpr_log(GPR_ERROR, "Enclave handshaker creation failed with error %s.",
              tsi_result_to_string(result));
      return;
    }

    grpc_handshake_manager_add(
        handshake_mgr, grpc_security_handshaker_create(tsi_handshaker, this,
                                                       args));
  }
};

}  // namespace

grpc_core::RefCountedPtr<grpc_channel_security_connector>
grpc_enclave_channel_security_connector_create(
    grpc_core::RefCountedPtr<grpc_channel_credentials> channel_credentials,
    grpc_core::RefCountedPtr<grpc_call_credentials> request_metadata_creds,
    const char *target) {
  GRPC_API_TRACE(
      "grpc_enclave_channel_security_connector_create("
      "grpc_channel_credentials=%p, grpc_call_credentials=%p, target=%s)",
      3, (channel_credentials.get(), request_metadata_creds.get(), target));
  return grpc_core::MakeRefCounted<grpc_enclave_channel_security_connector>(
      channel_credentials, request_metadata_creds, target);
}

grpc_core::RefCountedPtr<grpc_server_security_connector>
grpc_enclave_server_security_connector_create(
    grpc_core::RefCountedPtr<grpc_server_credentials> server_credentials) {
  GRPC_API_TRACE(
      "grpc_enclave_server_security_connector_create("
      "grpc_server_credentials=%p)",
      1, (server_credentials.get()));
  return grpc_core::MakeRefCounted<grpc_enclave_server_security_connector>(
      server_credentials);
}
