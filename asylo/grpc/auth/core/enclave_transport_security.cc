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

#include "asylo/grpc/auth/core/enclave_transport_security.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <google/protobuf/io/coded_stream.h>
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "asylo/grpc/auth/core/client_ekep_handshaker.h"
#include "asylo/grpc/auth/core/ekep_handshaker.h"
#include "asylo/grpc/auth/core/ekep_handshaker_util.h"
#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/grpc/auth/core/server_ekep_handshaker.h"
#include "asylo/identity/delegating_identity_expectation_matcher.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/identity_acl_evaluator.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/statusor.h"
#include "include/grpc/support/log.h"
#include "src/core/lib/gpr/string.h"
#include "src/core/lib/surface/api_trace.h"
#include "src/core/tsi/alts/frame_protector/alts_frame_protector.h"
#include "src/core/tsi/transport_security.h"
#include "src/core/tsi/transport_security_interface.h"

namespace asylo {
namespace {

constexpr int kEnclavePeerPropertyCount = 4;

}  // namespace

// --- tsi_handshaker_result implementation. ---

// C++ implementation of tsi_handshaker_result.
class TsiEnclaveHandshakerResult {
 public:
  TsiEnclaveHandshakerResult(
      bool is_client, RecordProtocol record_protocol,
      const CleansingVector<uint8_t> &record_protocol_key,
      std::unique_ptr<EnclaveIdentities> peer_identities,
      std::string unused_bytes)
      : is_client_(is_client),
        record_protocol_(record_protocol),
        record_protocol_key_(record_protocol_key),
        peer_identities_(std::move(peer_identities)),
        unused_bytes_(std::move(unused_bytes)) {}

  // Creates a frame protector that uses a max frame size of
  // |max_output_protected_frame_size|, if non-null, and places the result in
  // |protector|.
  tsi_result CreateFrameProtector(size_t *max_output_protected_frame_size,
                                  tsi_frame_protector **protector) {
    switch (record_protocol_) {
      case ALTSRP_AES128_GCM:
        return alts_create_frame_protector(
            record_protocol_key_.data(), record_protocol_key_.size(),
            is_client_, /*is_rekey=*/false, max_output_protected_frame_size,
            protector);
      default:
        return TSI_INTERNAL_ERROR;
    }
  }

  // Sets |bytes| to the unused bytes from the handshake, if any, and sets
  // |bytes_size| to the number of unused bytes.
  tsi_result GetUnusedBytes(const unsigned char **bytes, size_t *bytes_size) {
    *bytes_size = unused_bytes_.size();
    *bytes = reinterpret_cast<const unsigned char *>(unused_bytes_.data());
    return TSI_OK;
  }

  // Extracts the peer's identity into |peer|. The resulting peer has the
  // following peer properties:
  //   * TSI_CERTIFICATE_TYPE_PEER_PROPERTY
  //   * TSI_SECURITY_LEVEL_PEER_PROPERTY
  //   * TSI_ENCLAVE_IDENTITIES_PROTO_PEER_PROPERTY
  //   * TSI_ENCLAVE_RECORD_PROTOCOL_PEER_PROPERTY
  tsi_result ExtractPeer(tsi_peer *peer) {
    tsi_result result = tsi_construct_peer(kEnclavePeerPropertyCount, peer);
    if (result != TSI_OK) {
      return result;
    }
    // Set the certificate type.
    result = tsi_construct_string_peer_property_from_cstring(
        TSI_CERTIFICATE_TYPE_PEER_PROPERTY, TSI_ENCLAVE_CERTIFICATE_TYPE,
        &peer->properties[0]);
    if (result != TSI_OK) {
      tsi_peer_destruct(peer);
      return result;
    }

    // Set the identities proto property.
    std::string serialized_identity;
    if (!peer_identities_->SerializeToString(&serialized_identity)) {
      tsi_peer_destruct(peer);
      return TSI_INTERNAL_ERROR;
    }
    result = tsi_construct_string_peer_property(
        TSI_ENCLAVE_IDENTITIES_PROTO_PEER_PROPERTY, serialized_identity.data(),
        serialized_identity.size(), &peer->properties[1]);
    if (result != TSI_OK) {
      tsi_peer_destruct(peer);
      return result;
    }

    // Set the record protocol property. Note that this property stores the enum
    // value encoded as a 32-bit little-endian number rather than the name of
    // the enum value.
    std::vector<uint8_t> serialized_record_protocol(sizeof(record_protocol_));
    google::protobuf::io::CodedOutputStream::WriteLittleEndian32ToArray(
        record_protocol_, serialized_record_protocol.data());
    result = tsi_construct_string_peer_property(
        TSI_ENCLAVE_RECORD_PROTOCOL_PEER_PROPERTY,
        reinterpret_cast<const char *>(serialized_record_protocol.data()),
        serialized_record_protocol.size(), &peer->properties[2]);
    if (result != TSI_OK) {
      tsi_peer_destruct(peer);
      return result;
    }
    result = tsi_construct_string_peer_property_from_cstring(
        TSI_SECURITY_LEVEL_PEER_PROPERTY,
        tsi_security_level_to_string(TSI_PRIVACY_AND_INTEGRITY),
        &peer->properties[3]);
    if (result != TSI_OK) {
      tsi_peer_destruct(peer);
      return result;
    }
    return result;
  }

 private:
  // True if this is a client handshaker result. Required for configuration of
  // the frame protector.
  bool is_client_;

  // The record protocol to use for frame protection.
  RecordProtocol record_protocol_;

  // The record protocol key to use for frame protection.
  CleansingVector<uint8_t> record_protocol_key_;

  // The peer's enclave identities.
  std::unique_ptr<EnclaveIdentities> peer_identities_;

  // Unused bytes leftover at the end of the EKEP handshake.
  std::string unused_bytes_;
};

// Implementation of tsi_handshaker_result that delegates all calls to a
// TsiEnclaveHandshakerResult object.
struct tsi_enclave_handshaker_result {
  tsi_handshaker_result base;
  std::unique_ptr<TsiEnclaveHandshakerResult> impl;
};

tsi_result enclave_handshaker_result_extract_peer(
    const tsi_handshaker_result *self, tsi_peer *peer) {
  const tsi_enclave_handshaker_result *result =
      reinterpret_cast<const tsi_enclave_handshaker_result *>(self);

  return result->impl->ExtractPeer(peer);
}

tsi_result enclave_handshaker_result_create_frame_protector(
    const tsi_handshaker_result *self, size_t *max_output_protected_frame_size,
    tsi_frame_protector **protector) {
  const tsi_enclave_handshaker_result *result =
      reinterpret_cast<const tsi_enclave_handshaker_result *>(self);

  return result->impl->CreateFrameProtector(max_output_protected_frame_size,
                                            protector);
}

tsi_result enclave_handshaker_result_get_unused_bytes(
    const tsi_handshaker_result *self, const unsigned char **bytes,
    size_t *bytes_size) {
  const tsi_enclave_handshaker_result *result =
      reinterpret_cast<const tsi_enclave_handshaker_result *>(self);

  return result->impl->GetUnusedBytes(bytes, bytes_size);
}

void enclave_handshaker_result_destroy(tsi_handshaker_result *self) {
  tsi_enclave_handshaker_result *result =
      reinterpret_cast<tsi_enclave_handshaker_result *>(self);
  delete (result);
}

const tsi_handshaker_result_vtable handshaker_result_vtable = {
    enclave_handshaker_result_extract_peer,
    nullptr /* create_zero_copy_grpc_protector */,
    enclave_handshaker_result_create_frame_protector,
    enclave_handshaker_result_get_unused_bytes,
    enclave_handshaker_result_destroy,
};

tsi_result enclave_handshaker_result_create(
    std::unique_ptr<TsiEnclaveHandshakerResult> impl,
    tsi_handshaker_result **handshaker_result) {
  if (!impl || !handshaker_result) {
    return TSI_INVALID_ARGUMENT;
  }

  tsi_enclave_handshaker_result *result = new tsi_enclave_handshaker_result();
  result->base.vtable = &handshaker_result_vtable;
  result->impl = std::move(impl);

  *handshaker_result = &result->base;
  return TSI_OK;
}

// --- tsi_handshaker implementation. ---

// Implementation of tsi_handshaker that uses an underlying EkepHandshaker
// object to perform an Enclave Key Exchange Protocol (EKEP) handshake.
struct tsi_enclave_handshaker {
  tsi_handshaker base;
  bool is_client;
  const absl::optional<IdentityAclPredicate> peer_acl;
  std::unique_ptr<EkepHandshaker> handshaker;
  std::string outgoing_bytes;

  tsi_enclave_handshaker(bool is_client,
                         const absl::optional<IdentityAclPredicate> &peer_acl,
                         std::unique_ptr<EkepHandshaker> ekep_handshaker);

  tsi_result evaluate_acl(const std::vector<EnclaveIdentity> &identities);
};

void enclave_handshaker_destroy(tsi_handshaker *self) {
  tsi_enclave_handshaker *impl =
      reinterpret_cast<tsi_enclave_handshaker *>(self);
  delete (impl);
}

tsi_result enclave_handshaker_next(
    tsi_handshaker *self, const unsigned char *received_bytes,
    size_t received_bytes_size, const unsigned char **bytes_to_send,
    size_t *bytes_to_send_size, tsi_handshaker_result **handshaker_result,
    tsi_handshaker_on_next_done_cb cb, void *user_data) {
  if ((received_bytes_size > 0 && !received_bytes) || !bytes_to_send ||
      !bytes_to_send_size || !handshaker_result) {
    return TSI_INVALID_ARGUMENT;
  }
  gpr_log(GPR_INFO,
          "enclave_handshaker_next(self=%p, received_bytes=%p, "
          "received_bytes_size=%zu, bytes_to_send=%p, bytes_to_send_size=%p "
          "handshaker_result=%p, cb=%p, user_data=%p)",
          self, received_bytes, received_bytes_size, bytes_to_send,
          bytes_to_send_size, handshaker_result, cb, user_data);

  tsi_enclave_handshaker *tsi_handshaker =
      reinterpret_cast<tsi_enclave_handshaker *>(self);
  EkepHandshaker *handshaker = tsi_handshaker->handshaker.get();

  // Run the next step of the handshake.
  EkepHandshaker::Result handshake_step_result = handshaker->NextHandshakeStep(
      reinterpret_cast<const char *>(received_bytes), received_bytes_size,
      &tsi_handshaker->outgoing_bytes);

  // Write the outgoing bytes.
  if (!tsi_handshaker->outgoing_bytes.empty()) {
    *bytes_to_send = reinterpret_cast<const unsigned char *>(
        tsi_handshaker->outgoing_bytes.data());
    *bytes_to_send_size = tsi_handshaker->outgoing_bytes.size();
  }

  *handshaker_result = nullptr;
  switch (handshake_step_result) {
    case EkepHandshaker::Result::IN_PROGRESS:
      return TSI_OK;
    case EkepHandshaker::Result::NOT_ENOUGH_DATA:
      return TSI_INCOMPLETE_DATA;
    case EkepHandshaker::Result::COMPLETED: {
      // If the handshake has completed, extract the handshake results.
      StatusOr<std::string> unused_bytes_result = handshaker->GetUnusedBytes();
      if (!unused_bytes_result.ok()) {
        gpr_log(GPR_ERROR, "Failed to retrieve unused bytes: %s",
                std::string(unused_bytes_result.status().message()).c_str());
        return TSI_INTERNAL_ERROR;
      }

      StatusOr<RecordProtocol> record_protocol_result =
          handshaker->GetRecordProtocol();
      if (!record_protocol_result.ok()) {
        gpr_log(GPR_ERROR, "Failed to retrieve record protocol: %s",
                std::string(record_protocol_result.status().message()).c_str());
        return TSI_INTERNAL_ERROR;
      }

      StatusOr<CleansingVector<uint8_t>> key_result =
          handshaker->GetRecordProtocolKey();
      if (!key_result.ok()) {
        gpr_log(GPR_ERROR, "Failed to retrieve record protocol key: %s",
                std::string(key_result.status().message()).c_str());
        return TSI_INTERNAL_ERROR;
      }

      StatusOr<std::unique_ptr<EnclaveIdentities>> identities_result =
          handshaker->GetPeerIdentities();
      if (!identities_result.ok()) {
        gpr_log(GPR_ERROR, "Failed to retrieve peer identities: %s",
                std::string(identities_result.status().message()).c_str());
        return TSI_INTERNAL_ERROR;
      }

      std::unique_ptr<EnclaveIdentities> identities =
          std::move(identities_result).value();

      tsi_result acl_eval_result = tsi_handshaker->evaluate_acl(
          {identities->identities().begin(), identities->identities().end()});
      if (acl_eval_result != TSI_OK) {
        return acl_eval_result;
      }

      // Create the handshaker result object.
      tsi_result result = enclave_handshaker_result_create(
          absl::make_unique<TsiEnclaveHandshakerResult>(
              tsi_handshaker->is_client, record_protocol_result.value(),
              key_result.value(), std::move(identities),
              unused_bytes_result.value()),
          handshaker_result);
      if (result == TSI_OK) {
        self->handshaker_result_created = true;
      }
      return result;
    }
    case EkepHandshaker::Result::ABORTED:
    default:
      return TSI_PROTOCOL_FAILURE;
  }
}

const tsi_handshaker_vtable handshaker_vtable = {
    nullptr /* get_bytes_to_send_to_peer -- deprecated */,
    nullptr /* process_bytes_from_peer   -- deprecated */,
    nullptr /* get_result                -- deprecated */,
    nullptr /* extract_peer              -- deprecated */,
    nullptr /* create_frame_protector    -- deprecated */,
    enclave_handshaker_destroy, enclave_handshaker_next,
    nullptr /* handshaker shutdown */,
};

tsi_enclave_handshaker::tsi_enclave_handshaker(
    bool is_client, const absl::optional<IdentityAclPredicate> &peer_acl,
    std::unique_ptr<EkepHandshaker> ekep_handshaker)
    : is_client(is_client),
      peer_acl(peer_acl),
      handshaker(std::move(ekep_handshaker)) {
  base.handshaker_result_created = false;
  base.handshake_shutdown = false;
  base.vtable = &handshaker_vtable;
}

tsi_result tsi_enclave_handshaker::evaluate_acl(
    const std::vector<EnclaveIdentity> &identities) {
  if (!peer_acl.has_value()) {
    return TSI_OK;
  }
  DelegatingIdentityExpectationMatcher matcher;
  std::string explanation;
  StatusOr<bool> acl_result =
      EvaluateIdentityAcl(identities, peer_acl.value(), matcher, &explanation);
  if (!acl_result.ok()) {
    gpr_log(GPR_ERROR, "Error evaluating ACL: %s",
            acl_result.status().ToString().c_str());
    return TSI_INTERNAL_ERROR;
  }
  if (!acl_result.value()) {
    gpr_log(GPR_ERROR, "Identities did not match ACL: %s", explanation.c_str());
    return TSI_PERMISSION_DENIED;
  }
  return TSI_OK;
}

}  // namespace asylo

tsi_result tsi_enclave_handshaker_create(
    bool is_client, absl::Span<asylo::AssertionDescription> self_assertions,
    absl::Span<asylo::AssertionDescription> accepted_peer_assertions,
    absl::string_view additional_authenticated_data,
    const absl::optional<asylo::IdentityAclPredicate> &peer_acl,
    tsi_handshaker **handshaker) {
  GRPC_API_TRACE(
      "tsi_enclave_handshaker_create(is_client=%d, self_assertions=%p, "
      "accepted_peer_assertions=%p, additional_authenticated_data=%p, "
      "peer_acl=%d, handshaker=%p)",
      6,
      (is_client, self_assertions.data(), accepted_peer_assertions.data(),
       additional_authenticated_data.data(), peer_acl.has_value(), handshaker));

  // Convert arguments to handshaker options.
  asylo::EkepHandshakerOptions options;
  options.additional_authenticated_data =
      std::string(additional_authenticated_data);
  options.self_assertions = {self_assertions.cbegin(), self_assertions.cend()};
  options.accepted_peer_assertions = {accepted_peer_assertions.cbegin(),
                                      accepted_peer_assertions.cend()};

  if (!options.additional_authenticated_data.empty()) {
    gpr_log(GPR_DEBUG, "additional authenticated data: %s",
            options.additional_authenticated_data.c_str());
  }
  for (const asylo::AssertionDescription &desc : options.self_assertions) {
    gpr_log(GPR_DEBUG, "self assertion: (%s)", desc.ShortDebugString().c_str());
  }
  for (const asylo::AssertionDescription &desc :
       options.accepted_peer_assertions) {
    gpr_log(GPR_DEBUG, "accepted peer assertion: (%s)",
            desc.ShortDebugString().c_str());
  }

  if (peer_acl.has_value()) {
    gpr_log(GPR_DEBUG, "accepted peer ACL: (%s)",
            peer_acl.value().ShortDebugString().c_str());
  }

  // Create an EkepHandshaker object and wrap it with a tsi_handshaker object.
  std::unique_ptr<asylo::EkepHandshaker> ekep_handshaker =
      is_client ? asylo::ClientEkepHandshaker::Create(options)
                : asylo::ServerEkepHandshaker::Create(options);
  if (!ekep_handshaker) {
    return TSI_INTERNAL_ERROR;
  }

  asylo::tsi_enclave_handshaker *tsi_handshaker =
      new asylo::tsi_enclave_handshaker(is_client, peer_acl,
                                        std::move(ekep_handshaker));

  *handshaker = &tsi_handshaker->base;
  return TSI_OK;
}
