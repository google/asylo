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

#include "asylo/grpc/auth/core/server_ekep_handshaker.h"

#include <openssl/curve25519.h>
#include <openssl/rand.h>

#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/util/logging.h"
#include "asylo/grpc/auth/core/ekep_crypto.h"
#include "asylo/grpc/auth/core/ekep_errors.h"
#include "asylo/grpc/auth/core/ekep_handshaker_util.h"
#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

// Returns true if |ekep_version|.name() is |version_name|.
bool CheckEkepVersionEquality(const EkepVersion &ekep_version,
                              const std::string &version_name) {
  return ekep_version.name() == version_name;
}

}  // namespace

std::unique_ptr<EkepHandshaker> ServerEkepHandshaker::Create(
    const EkepHandshakerOptions &options) {
  Status status = options.Validate();
  if (!status.ok()) {
    LOG(ERROR) << "Invalid handshaker options: " << status;
    return nullptr;
  }
  return absl::WrapUnique(new ServerEkepHandshaker(options));
}

ServerEkepHandshaker::ServerEkepHandshaker(const EkepHandshakerOptions &options)
    : EkepHandshaker(options.max_frame_size),
      self_assertions_(options.self_assertions),
      accepted_peer_assertions_(options.accepted_peer_assertions),
      available_cipher_suites_({CURVE25519_SHA256}),
      available_record_protocols_({ALTSRP_AES128_GCM}),
      available_ekep_versions_({"EKEP v1"}),
      additional_authenticated_data_(options.additional_authenticated_data),
      selected_cipher_suite_(UNKNOWN_HANDSHAKE_CIPHER),
      selected_record_protocol_(UNKNOWN_RECORD_PROTOCOL),
      expected_message_type_(CLIENT_PRECOMMIT),
      // The handshake is in progress for the server because it relies on the
      // client to act first.
      handshaker_state_(EkepHandshaker::HandshakeState::IN_PROGRESS) {}

bool ServerEkepHandshaker::IsHandshakeInProgress() const {
  return handshaker_state_ == HandshakeState::IN_PROGRESS;
}

bool ServerEkepHandshaker::IsHandshakeCompleted() const {
  return handshaker_state_ == HandshakeState::COMPLETED;
}

bool ServerEkepHandshaker::IsHandshakeAborted() const {
  return handshaker_state_ == HandshakeState::ABORTED;
}

HandshakeMessageType ServerEkepHandshaker::GetExpectedMessageType() const {
  if (!IsHandshakeInProgress()) {
    return UNKNOWN_HANDSHAKE_MESSAGE;
  }
  return expected_message_type_;
}

ServerEkepHandshaker::Result ServerEkepHandshaker::StartHandshake(
    std::string *output) {
  LOG(DFATAL) << "StartHandshake() was called on a ServerEkepHandshaker";
  AbortHandshake(EkepError(Abort::PROTOCOL_ERROR,
                           "Server cannot start an EKEP handshaker"),
                 output);
  return Result::ABORTED;
}

void ServerEkepHandshaker::AbortHandshake(const Status &abort_status,
                                          std::string *output) {
  Abort_ErrorCode error_code = GetEkepErrorCode(abort_status).value();
  LOG(ERROR) << abort_status;

  Abort abort;
  abort.set_code(error_code);
  abort.set_message(std::string(abort_status.message()));

  google::protobuf::io::StringOutputStream outgoing_frame(output);
  Status status = EncodeFrame(ABORT, abort, &outgoing_frame);
  if (!status.ok()) {
    // An error occurred while attempting to notify the peer of another error.
    // There is nothing left to do at this point.
    LOG(ERROR) << "Encoding of ABORT message failed: " << status;
  }

  handshaker_state_ = HandshakeState::ABORTED;
}

ServerEkepHandshaker::Result ServerEkepHandshaker::HandleHandshakeMessage(
    HandshakeMessageType message_type, const google::protobuf::Message &handshake_message,
    std::string *output) {
  Status status = absl::OkStatus();

  switch (message_type) {
    case CLIENT_PRECOMMIT:
      expected_message_type_ = CLIENT_ID;
      status = HandleClientPrecommit(handshake_message, output);
      break;
    case CLIENT_ID:
      expected_message_type_ = CLIENT_FINISH;
      status = HandleClientId(handshake_message, output);
      break;
    case CLIENT_FINISH:
      expected_message_type_ = UNKNOWN_HANDSHAKE_MESSAGE;
      status = HandleClientFinish(handshake_message);
      if (status.ok()) {
        handshaker_state_ = HandshakeState::COMPLETED;
      }
      break;
    default:
      // This should never happen because the message_type should be verified
      // before calling this method.
      status =
          EkepError(Abort::BAD_MESSAGE, "Unrecognized handshake message type");
  }
  if (!status.ok()) {
    if (message_type != CLIENT_FINISH) {
      // No messages can be sent after ClientFinish.
      AbortHandshake(status, output);
    }
    handshaker_state_ = HandshakeState::ABORTED;
  }

  // If the handshake has completed successfully, derive the record protocol
  // key. Any errors that occur during derivation of the record protocol key do
  // not result in an Abort message being sent to the peer.
  if (IsHandshakeCompleted()) {
    if (!DeriveAndSetRecordProtocolKey(
             selected_cipher_suite_, selected_record_protocol_, primary_secret_)
             .ok()) {
      handshaker_state_ = HandshakeState::ABORTED;
    }
  }

  switch (handshaker_state_) {
    case HandshakeState::COMPLETED:
      return Result::COMPLETED;
    case HandshakeState::IN_PROGRESS:
      return Result::IN_PROGRESS;
    default:
      return Result::ABORTED;
  }
}

void ServerEkepHandshaker::HandleAbortMessage(const Abort *abort_message) {
  if (abort_message) {
    LOG(ERROR) << "Received " << ProtoEnumValueName(abort_message->code())
               << " from client: " << abort_message->message();
  }

  handshaker_state_ = HandshakeState::ABORTED;
}

Status ServerEkepHandshaker::HandleClientPrecommit(
    const google::protobuf::Message &message, std::string *output) {
  const auto *client_precommit_ptr =
      dynamic_cast<const ClientPrecommit *>(&message);
  if (!client_precommit_ptr) {
    LOG(QFATAL) << "HandleClientPrecommit() was passed a non-ClientPrecommit "
                << "handshake message";
    return EkepError(Abort::INTERNAL_ERROR, "Internal error");
  }
  const ClientPrecommit &client_precommit = *client_precommit_ptr;

  // Choose the first compatible EKEP version offered by the client.
  if (!SetSelectedEkepVersion(client_precommit.available_ekep_versions())) {
    return EkepError(Abort::BAD_PROTOCOL_VERSION,
                     "No compatible EKEP protocol version");
  }

  // Choose the first compatible cipher suite offered by the client.
  if (!SetSelectedCipherSuite(client_precommit.available_cipher_suites())) {
    return EkepError(Abort::BAD_HANDSHAKE_CIPHER, "No compatible cipher suite");
  }

  // Set the transcript hash function using the selected cipher suite.
  switch (selected_cipher_suite_) {
    case CURVE25519_SHA256:
      SetTranscriptHashFunction(new Sha256Hash());
      break;
    default:
      LOG(ERROR) << "Server handshaker has bad cipher suite configuration"
                 << ProtoEnumValueName(selected_cipher_suite_);
      return EkepError(Abort::INTERNAL_ERROR,
                       "Error using selected cipher suite");
  }

  // Choose the first compatible record protocol offered by the client.
  if (!SetSelectedRecordProtocol(
          client_precommit.available_record_protocols())) {
    return EkepError(Abort::BAD_RECORD_PROTOCOL,
                     "No compatible record_protocol");
  }

  // Verify that the client sent an adequately-sized challenge.
  if (client_precommit.challenge().size() != kEkepChallengeSize) {
    return EkepError(Abort::PROTOCOL_ERROR,
                     "Received a challenge with incorrect size");
  }

  for (const AssertionOffer &offer : client_precommit.client_offers()) {
    const AssertionDescription &offer_desc = offer.description();
    // Request any assertion that the peer offered and that this handshaker is
    // capable of verifying.
    if (FindAssertionDescription(accepted_peer_assertions_, offer_desc) !=
        accepted_peer_assertions_.cend()) {
      auto result = GetEnclaveAssertionVerifier(offer_desc)->CanVerify(offer);
      if (result.ok() && result.value()) {
        expected_peer_assertions_.push_back(offer_desc);
      }
    }
  }
  if (expected_peer_assertions_.empty()) {
    return EkepError(Abort::BAD_ASSERTION_TYPE,
                     "No acceptable client assertion offers");
  }

  for (const AssertionRequest &request : client_precommit.client_requests()) {
    const AssertionDescription &request_desc = request.description();
    // Offer any assertions that the peer requested and that this handshaker is
    // capable of generating. Note that assertion generators were verified
    // during creation of the handshaker so there is no need to check whether
    // the call to GetEnclaveAssertionGenerator() returns nullptr.
    if (FindAssertionDescription(self_assertions_, request_desc) !=
        self_assertions_.cend()) {
      auto result =
          GetEnclaveAssertionGenerator(request_desc)->CanGenerate(request);
      if (result.ok() && result.value()) {
        promised_assertions_.push_back(request);
      }
    }
  }
  if (promised_assertions_.empty()) {
    return EkepError(Abort::BAD_ASSERTION_TYPE,
                     "No acceptable client assertion requests");
  }

  return WriteServerPrecommit(output);
}

Status ServerEkepHandshaker::HandleClientId(const google::protobuf::Message &message,
                                            std::string *output) {
  const auto *client_id_ptr = dynamic_cast<const ClientId *>(&message);
  if (!client_id_ptr) {
    LOG(QFATAL) << "HandleClientId() was passed a non-ClientId handshake "
                << "message";
    return EkepError(Abort::INTERNAL_ERROR, "Internal error");
  }
  const ClientId &client_id = *client_id_ptr;

  // The client's assertions should all be bound to a data blob containing a
  // hash of the transcript up to and including the ServerPrecommit message, and
  // the server's public key.
  std::string ekep_context;
  if (!MakeEkepContextBlob(client_id.dh_public_key(),
                           client_assertion_transcript_, &ekep_context)) {
    return EkepError(Abort::INTERNAL_ERROR, "Failed to generate context");
  }

  for (const Assertion &assertion : client_id.assertions()) {
    auto desc_it = FindAssertionDescription(expected_peer_assertions_,
                                            assertion.description());
    if (desc_it == expected_peer_assertions_.cend()) {
      return EkepError(Abort::BAD_ASSERTION,
                       "Client provided an assertion that was not previously "
                       "requested");
    }

    EnclaveIdentity identity;
    // Note that assertion verifiers were verified during creation of the
    // handshaker so there is no need to check whether the call to
    // GetEnclaveAssertionVerifier() returns nullptr.
    Status status = GetEnclaveAssertionVerifier(assertion.description())
                        ->Verify(ekep_context, assertion, &identity);
    if (!status.ok()) {
      LOG(ERROR) << "Assertion could not be verified: " << status;
      return EkepError(Abort::BAD_ASSERTION, "Assertion could not be verified");
    }
    AddPeerIdentity(identity);
    expected_peer_assertions_.erase(desc_it);
  }

  if (!expected_peer_assertions_.empty()) {
    // The client did not provide all the expected assertions.
    return EkepError(Abort::BAD_ASSERTION,
                     "Client did not provide all expected assertions");
  }

  std::copy(client_id.dh_public_key().cbegin(),
            client_id.dh_public_key().cend(),
            std::back_inserter(client_public_key_));

  return WriteServerId(output);
}

Status ServerEkepHandshaker::HandleClientFinish(
    const google::protobuf::Message &message) {
  const auto *client_finish_ptr = dynamic_cast<const ClientFinish *>(&message);
  if (!client_finish_ptr) {
    LOG(DFATAL) << "HandleClientFinish() was passed a non-ClientFinish "
                << "handshake message";
    return EkepError(Abort::INTERNAL_ERROR, "Internal error");
  }
  const ClientFinish &client_finish = *client_finish_ptr;

  CleansingVector<uint8_t> actual_client_handshake_authenticator;
  std::copy(client_finish.handshake_authenticator().cbegin(),
            client_finish.handshake_authenticator().cend(),
            std::back_inserter(actual_client_handshake_authenticator));

  // Compute the client handshake authenticator.
  CleansingVector<uint8_t> expected_client_handshake_authenticator;
  ASYLO_RETURN_IF_ERROR(ComputeClientHandshakeAuthenticator(
      selected_cipher_suite_, authenticator_secret_,
      &expected_client_handshake_authenticator));

  // Validate the client's handshake authenticator value.
  if (!CheckMacEquality(expected_client_handshake_authenticator,
                        actual_client_handshake_authenticator)) {
    return EkepError(Abort::BAD_AUTHENTICATOR,
                     "Client handshake authenticator value is incorrect");
  }
  return absl::OkStatus();
}

Status ServerEkepHandshaker::WriteServerPrecommit(std::string *output) {
  ServerPrecommit server_precommit;

  server_precommit.mutable_selected_ekep_version()->set_name(
      selected_ekep_version_);
  server_precommit.set_selected_cipher_suite(selected_cipher_suite_);
  server_precommit.set_selected_record_protocol(selected_record_protocol_);

  if (!additional_authenticated_data_.empty()) {
    server_precommit.mutable_options()->set_data(
        additional_authenticated_data_);
  }

  std::vector<uint8_t> challenge(kEkepChallengeSize);
  if (RAND_bytes(challenge.data(), kEkepChallengeSize) != 1) {
    return EkepError(Abort::INTERNAL_ERROR, "Internal error");
  }
  server_precommit.set_challenge(challenge.data(), challenge.size());

  for (const AssertionRequest &request : promised_assertions_) {
    const AssertionDescription &description = request.description();
    // Note that assertion generators were verified during creation of the
    // handshaker so there is no need to check whether the call to
    // GetEnclaveAssertionGenerator() returns nullptr.
    GetEnclaveAssertionGenerator(description)
        ->CreateAssertionOffer(server_precommit.add_server_offers());
  }

  for (const AssertionDescription &description : expected_peer_assertions_) {
    // Note that assertion verifiers were verified during creation of the
    // handshaker so there is no need to check whether the call to
    // GetEnclaveAssertionVerifier() returns nullptr.
    GetEnclaveAssertionVerifier(description)
        ->CreateAssertionRequest(server_precommit.add_server_requests());
  }

  ASYLO_RETURN_IF_ERROR(WriteFrameAndUpdateTranscript(
      SERVER_PRECOMMIT, server_precommit, output));

  // At this stage in the protocol, the transcript is:
  //   hash(ClientPrecommit || ServerPrecommit)
  //
  // The client will bind its assertions to this transcript so the server must
  // save a snapshot of the transcript at this time.
  return GetTranscriptHash(&client_assertion_transcript_);
}

Status ServerEkepHandshaker::WriteServerId(std::string *output) {
  // Generate an ephemeral Diffie-Hellman key-pair for the negotiated cipher
  // suite.
  switch (selected_cipher_suite_) {
    case CURVE25519_SHA256:
      dh_public_key_.resize(X25519_PUBLIC_VALUE_LEN);
      dh_private_key_.resize(X25519_PRIVATE_KEY_LEN);
      X25519_keypair(dh_public_key_.data(), dh_private_key_.data());
      break;
    default:
      LOG(ERROR) << "Server handshaker has bad cipher suite configuration";
      return EkepError(Abort::INTERNAL_ERROR,
                       "Error using selected cipher suite");
  }

  ServerId server_id;
  server_id.set_dh_public_key(dh_public_key_.data(), dh_public_key_.size());

  std::string public_key(reinterpret_cast<const char *>(dh_public_key_.data()),
                         dh_public_key_.size());

  // At this stage in the protocol, the transcript is:
  //   hash(ClientPrecommit || ServerPrecommit || ClientId)
  //
  // The server binds its assertions to this transcript.
  std::string transcript_hash;
  ASYLO_RETURN_IF_ERROR(GetTranscriptHash(&transcript_hash));

  // Each assertion generated by the server is bound to a data blob containing a
  // hash of the current transcript and the server's public key.
  std::string ekep_context;
  if (!MakeEkepContextBlob(public_key, transcript_hash, &ekep_context)) {
    return EkepError(Abort::INTERNAL_ERROR, "Assertion generation failed");
  }

  // Generate all assertions that the client requested and that the server
  // offered.
  for (const AssertionRequest &request : promised_assertions_) {
    // Note that assertion generators were verified during creation of the
    // handshaker so there is no need to check whether the call to
    // GetEnclaveAssertionGenerator() returns nullptr.
    Status status =
        GetEnclaveAssertionGenerator(request.description())
            ->Generate(ekep_context, request, server_id.add_assertions());
    if (!status.ok()) {
      LOG(ERROR) << "Assertion generation failed: " << status;
      return EkepError(Abort::INTERNAL_ERROR, "Assertion generation failed");
    }
  }

  ASYLO_RETURN_IF_ERROR(
      WriteFrameAndUpdateTranscript(SERVER_ID, server_id, output));

  return WriteServerFinish(output);
}

Status ServerEkepHandshaker::WriteServerFinish(std::string *output) {
  // At this stage in the protocol, the transcript is:
  //   hash(ClientPrecommit || ServerPrecommit || ClientId || ServerId)
  //
  // This transcript is used by both the client and server to derive the EKEP
  // secrets.
  std::string transcript_hash;
  ASYLO_RETURN_IF_ERROR(GetTranscriptHash(&transcript_hash));

  ASYLO_RETURN_IF_ERROR(
      DeriveSecrets(selected_cipher_suite_, transcript_hash, client_public_key_,
                    dh_private_key_, &primary_secret_, &authenticator_secret_));

  CleansingVector<uint8_t> authenticator;
  ASYLO_RETURN_IF_ERROR(ComputeServerHandshakeAuthenticator(
      selected_cipher_suite_, authenticator_secret_, &authenticator));

  ServerFinish server_finish;
  server_finish.set_handshake_authenticator(authenticator.data(),
                                            authenticator.size());

  return WriteFrameAndUpdateTranscript(SERVER_FINISH, server_finish, output);
}

bool ServerEkepHandshaker::SetSelectedEkepVersion(
    const google::protobuf::RepeatedPtrField<EkepVersion> &ekep_versions) {
  // Choose the first compatible EKEP version available.
  auto version_it = std::find_first_of(
      ekep_versions.cbegin(), ekep_versions.cend(),
      available_ekep_versions_.cbegin(), available_ekep_versions_.cend(),
      CheckEkepVersionEquality);
  if (version_it == ekep_versions.cend()) {
    return false;
  }

  selected_ekep_version_ = version_it->name();
  return true;
}

bool ServerEkepHandshaker::SetSelectedCipherSuite(
    const google::protobuf::RepeatedField<int> &cipher_suites) {
  // Choose the first compatible cipher suite available.
  auto cipher_it = std::find_first_of(
      cipher_suites.cbegin(), cipher_suites.cend(),
      available_cipher_suites_.cbegin(), available_cipher_suites_.cend());
  if (cipher_it == cipher_suites.cend()) {
    return false;
  }

  selected_cipher_suite_ = static_cast<HandshakeCipher>(*cipher_it);
  return true;
}

bool ServerEkepHandshaker::SetSelectedRecordProtocol(
    const google::protobuf::RepeatedField<int> &record_protocols) {
  // Choose the first compatible record protocol offered by the client.
  auto protocol_it = std::find_first_of(
      record_protocols.cbegin(), record_protocols.cend(),
      available_record_protocols_.cbegin(), available_record_protocols_.cend());
  if (protocol_it == record_protocols.cend()) {
    return false;
  }

  selected_record_protocol_ = static_cast<RecordProtocol>(*protocol_it);
  SetRecordProtocol(selected_record_protocol_);
  return true;
}

}  // namespace asylo
