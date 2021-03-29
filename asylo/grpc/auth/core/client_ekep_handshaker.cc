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

#include "asylo/grpc/auth/core/client_ekep_handshaker.h"

#include <openssl/curve25519.h>
#include <openssl/rand.h>

#include <algorithm>

#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
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

std::unique_ptr<EkepHandshaker> ClientEkepHandshaker::Create(
    const EkepHandshakerOptions &options) {
  Status status = options.Validate();
  if (!status.ok()) {
    LOG(ERROR) << "Invalid handshaker options: " << status;
    return nullptr;
  }
  return absl::WrapUnique(new ClientEkepHandshaker(options));
}

ClientEkepHandshaker::ClientEkepHandshaker(const EkepHandshakerOptions &options)
    : EkepHandshaker(options.max_frame_size),
      self_assertions_(options.self_assertions),
      accepted_peer_assertions_(options.accepted_peer_assertions),
      available_cipher_suites_({CURVE25519_SHA256}),
      available_record_protocols_({ALTSRP_AES128_GCM}),
      available_ekep_versions_({"EKEP v1"}),
      additional_authenticated_data_(options.additional_authenticated_data),
      selected_cipher_suite_(UNKNOWN_HANDSHAKE_CIPHER),
      selected_record_protocol_(UNKNOWN_RECORD_PROTOCOL),
      expected_message_type_(SERVER_PRECOMMIT),
      handshaker_state_(EkepHandshaker::HandshakeState::NOT_STARTED) {}

bool ClientEkepHandshaker::IsHandshakeInProgress() const {
  return handshaker_state_ == HandshakeState::IN_PROGRESS;
}

bool ClientEkepHandshaker::IsHandshakeCompleted() const {
  return handshaker_state_ == HandshakeState::COMPLETED;
}

bool ClientEkepHandshaker::IsHandshakeAborted() const {
  return handshaker_state_ == HandshakeState::ABORTED;
}

HandshakeMessageType ClientEkepHandshaker::GetExpectedMessageType() const {
  if (!IsHandshakeInProgress()) {
    return UNKNOWN_HANDSHAKE_MESSAGE;
  }
  return expected_message_type_;
}

ClientEkepHandshaker::Result ClientEkepHandshaker::StartHandshake(
    std::string *output) {
  Status status = WriteClientPrecommit(output);
  if (!status.ok()) {
    AbortHandshake(status, output);
    return Result::ABORTED;
  }

  handshaker_state_ = HandshakeState::IN_PROGRESS;
  return Result::IN_PROGRESS;
}

void ClientEkepHandshaker::AbortHandshake(const Status &abort_status,
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

ClientEkepHandshaker::Result ClientEkepHandshaker::HandleHandshakeMessage(
    HandshakeMessageType message_type, const google::protobuf::Message &handshake_message,
    std::string *output) {
  Status status = absl::OkStatus();
  switch (message_type) {
    case SERVER_PRECOMMIT:
      expected_message_type_ = SERVER_ID;
      status = HandleServerPrecommit(handshake_message, output);
      break;
    case SERVER_ID:
      expected_message_type_ = SERVER_FINISH;
      status = HandleServerId(handshake_message);
      break;
    case SERVER_FINISH:
      expected_message_type_ = UNKNOWN_HANDSHAKE_MESSAGE;
      status = HandleServerFinish(handshake_message, output);
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
    AbortHandshake(status, output);
  }

  // If the handshake was successfully completed, derive the record protocol
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

void ClientEkepHandshaker::HandleAbortMessage(const Abort *abort_message) {
  if (abort_message) {
    LOG(ERROR) << "Received " << ProtoEnumValueName(abort_message->code())
               << " from server: " << abort_message->message();
  }

  handshaker_state_ = HandshakeState::ABORTED;
}

Status ClientEkepHandshaker::HandleServerPrecommit(
    const google::protobuf::Message &message, std::string *output) {
  const auto *server_precommit_ptr =
      dynamic_cast<const ServerPrecommit *>(&message);
  if (!server_precommit_ptr) {
    LOG(QFATAL) << "HandleServerPrecommit() was passed a non-ServerPrecommit "
                << "handshake message";
    return EkepError(Abort::INTERNAL_ERROR, "Internal error");
  }
  const ServerPrecommit &server_precommit = *server_precommit_ptr;

  const std::string &ekep_version =
      server_precommit.selected_ekep_version().name();
  if (!SetSelectedEkepVersion(ekep_version)) {
    return EkepError(
        Abort::PROTOCOL_ERROR,
        absl::StrCat("Selected EKEP version is invalid: ", ekep_version));
  }

  HandshakeCipher cipher_suite = server_precommit.selected_cipher_suite();
  if (!SetSelectedCipherSuite(cipher_suite)) {
    return EkepError(Abort::PROTOCOL_ERROR,
                     absl::StrCat("Selected cipher suite is invalid: ",
                                  ProtoEnumValueName(cipher_suite)));
  }

  // Use the selected cipher suite to set the transcript hash function.
  switch (selected_cipher_suite_) {
    case CURVE25519_SHA256:
      SetTranscriptHashFunction(new Sha256Hash());
      break;
    default:
      LOG(ERROR) << "Client handshaker has bad cipher suite configuration"
                 << ProtoEnumValueName(selected_cipher_suite_);
      return EkepError(Abort::INTERNAL_ERROR,
                       "Error using selected cipher suite");
  }

  RecordProtocol record_protocol = server_precommit.selected_record_protocol();
  if (!SetSelectedRecordProtocol(record_protocol)) {
    return EkepError(Abort::PROTOCOL_ERROR,
                     absl::StrCat("Selected record protocol is invalid: ",
                                  ProtoEnumValueName(record_protocol)));
  }

  // Verify that the server sent an adequately-sized challenge.
  if (server_precommit.challenge().size() != kEkepChallengeSize) {
    return EkepError(Abort::PROTOCOL_ERROR,
                     absl::StrCat("Challenge has incorrect size: ",
                                  server_precommit.challenge().size()));
  }

  // Verify that the server requested a non-empty subset of the assertions that
  // were offered by the client.
  if (server_precommit.server_requests().empty()) {
    return EkepError(Abort::PROTOCOL_ERROR,
                     "Server did not request any assertions");
  }
  for (const AssertionRequest &request : server_precommit.server_requests()) {
    if (FindAssertionDescription(self_assertions_, request.description()) ==
        self_assertions_.cend()) {
      return EkepError(
          Abort::PROTOCOL_ERROR,
          "Server requested an assertion that was not offered by the "
          "client");
    }
  }

  // Verify that the server offered a non-empty subset of the assertions that
  // were requested by the client.
  if (server_precommit.server_offers().empty()) {
    return EkepError(Abort::PROTOCOL_ERROR,
                     "Server did not offer any assertions");
  }
  for (const AssertionOffer &offer : server_precommit.server_offers()) {
    if (FindAssertionDescription(accepted_peer_assertions_,
                                 offer.description()) ==
        accepted_peer_assertions_.cend()) {
      return EkepError(
          Abort::PROTOCOL_ERROR,
          "Server offered an assertion that was not requested by the "
          "client");
    }
  }

  // Save a description of each assertion that is offered by the server. This
  // information is used later to validate the ServerId message.
  std::transform(
      server_precommit.server_offers().cbegin(),
      server_precommit.server_offers().cend(),
      std::back_inserter(expected_peer_assertions_),
      [](const AssertionOffer &offer) -> const AssertionDescription & {
        return offer.description();
      });

  return WriteClientId(server_precommit.server_requests().cbegin(),
                       server_precommit.server_requests().cend(), output);
}

Status ClientEkepHandshaker::HandleServerId(const google::protobuf::Message &message) {
  const auto *server_id_ptr = dynamic_cast<const ServerId *>(&message);
  if (!server_id_ptr) {
    LOG(QFATAL) << "HandleServerId() was passed a non-ServerId handshake "
                << "message";
    return EkepError(Abort::INTERNAL_ERROR, "Internal error");
  }
  const ServerId &server_id = *server_id_ptr;

  // The server's assertions should all be bound to a data blob containing a
  // hash of the transcript up to and including the ClientId message, and the
  // server's public key.
  std::string ekep_context;
  if (!MakeEkepContextBlob(server_id.dh_public_key(),
                           server_assertion_transcript_, &ekep_context)) {
    return EkepError(Abort::INTERNAL_ERROR, "Failed to generate context");
  }

  for (const Assertion &assertion : server_id.assertions()) {
    auto desc_it = FindAssertionDescription(expected_peer_assertions_,
                                            assertion.description());
    if (desc_it == expected_peer_assertions_.cend()) {
      return EkepError(Abort::BAD_ASSERTION,
                       "Server provided an assertion that was not previously "
                       "offered");
    }

    EnclaveIdentity identity;
    // Note that assertion verifiers were verified during creation of the
    // handshaker so there is no need to check whether the call to
    // GetEnclaveAssertionVerifier() returns nullptr.
    Status status =
        GetEnclaveAssertionVerifier(assertion.description())
            ->Verify(/*user_data=*/ekep_context, assertion, &identity);
    if (!status.ok()) {
      LOG(ERROR) << "Assertion could not be verified: " << status;
      return EkepError(Abort::BAD_ASSERTION, "Assertion could not be verified");
    }
    AddPeerIdentity(identity);
    expected_peer_assertions_.erase(desc_it);
  }

  if (!expected_peer_assertions_.empty()) {
    // The server did not provide all the expected assertions.
    return EkepError(Abort::BAD_ASSERTION,
                     "Server did not provide all expected assertions");
  }

  std::vector<uint8_t> server_public_key;
  std::copy(server_id.dh_public_key().cbegin(),
            server_id.dh_public_key().cend(),
            std::back_inserter(server_public_key));

  // Derive EKEP Primary and Authenticator secrets using the current transcript
  // and the server's public key.
  std::string transcript_hash;
  ASYLO_RETURN_IF_ERROR(GetTranscriptHash(&transcript_hash));
  return DeriveSecrets(selected_cipher_suite_, transcript_hash,
                       server_public_key, dh_private_key_, &primary_secret_,
                       &authenticator_secret_);
}

Status ClientEkepHandshaker::HandleServerFinish(const google::protobuf::Message &message,
                                                std::string *output) {
  const auto *server_finish_ptr = dynamic_cast<const ServerFinish *>(&message);
  if (!server_finish_ptr) {
    LOG(QFATAL) << "HandleServerFinish() was passed a non-ServerFinish "
                << "handshake message";
    return EkepError(Abort::INTERNAL_ERROR, "Internal error");
  }
  const ServerFinish &server_finish = *server_finish_ptr;

  CleansingVector<uint8_t> actual_server_handshake_authenticator;
  std::copy(server_finish.handshake_authenticator().cbegin(),
            server_finish.handshake_authenticator().cend(),
            std::back_inserter(actual_server_handshake_authenticator));

  // Compute the server handshake authenticator.
  CleansingVector<uint8_t> expected_server_handshake_authenticator;
  ASYLO_RETURN_IF_ERROR(ComputeServerHandshakeAuthenticator(
      selected_cipher_suite_, authenticator_secret_,
      &expected_server_handshake_authenticator));

  // Validate the server's handshake authenticator value.
  if (!CheckMacEquality(expected_server_handshake_authenticator,
                        actual_server_handshake_authenticator)) {
    return EkepError(Abort::BAD_AUTHENTICATOR,
                     "Server handshake authenticator value is incorrect");
  }

  return WriteClientFinish(output);
}

Status ClientEkepHandshaker::WriteClientPrecommit(std::string *output) {
  ClientPrecommit client_precommit;

  std::copy(available_cipher_suites_.begin(), available_cipher_suites_.end(),
            google::protobuf::RepeatedFieldBackInserter(
                client_precommit.mutable_available_cipher_suites()));

  std::copy(available_record_protocols_.begin(),
            available_record_protocols_.end(),
            google::protobuf::RepeatedFieldBackInserter(
                client_precommit.mutable_available_record_protocols()));

  for (const std::string &version_name : available_ekep_versions_) {
    EkepVersion *ekep_version = client_precommit.add_available_ekep_versions();
    ekep_version->set_name(version_name);
  }

  if (!additional_authenticated_data_.empty()) {
    client_precommit.mutable_options()->set_data(
        additional_authenticated_data_);
  }

  std::vector<uint8_t> challenge(kEkepChallengeSize);
  if (RAND_bytes(challenge.data(), kEkepChallengeSize) != 1) {
    return EkepError(Abort::INTERNAL_ERROR, "Internal error");
  }
  client_precommit.set_challenge(challenge.data(), challenge.size());

  for (const AssertionDescription &description : self_assertions_) {
    // Note that assertion generators were verified during creation of the
    // handshaker so there is no need to check whether the call to
    // GetEnclaveAssertionGenerator() returns nullptr.
    Status status =
        GetEnclaveAssertionGenerator(description)
            ->CreateAssertionOffer(client_precommit.add_client_offers());
    if (!status.ok()) {
      LOG(ERROR) << "Failed to create assertion offer for description"
                 << description.ShortDebugString() << ": " << status;
      return EkepError(Abort::INTERNAL_ERROR,
                       "Failed to create assertion offer");
    }
  }

  for (const AssertionDescription &description : accepted_peer_assertions_) {
    // Note that assertion verifiers were verified during creation of the
    // handshaker so there is no need to check whether the call to
    // GetEnclaveAssertionVerifier() returns nullptr.
    Status status =
        GetEnclaveAssertionVerifier(description)
            ->CreateAssertionRequest(client_precommit.add_client_requests());
    if (!status.ok()) {
      LOG(ERROR) << "Failed to create assertion request: " << status;
      return EkepError(Abort::INTERNAL_ERROR,
                       "Failed to create assertion request");
    }
  }

  // There is no need to save the transcript at this point in the handshake.
  return WriteFrameAndUpdateTranscript(CLIENT_PRECOMMIT, client_precommit,
                                       output);
}

Status ClientEkepHandshaker::WriteClientId(
    google::protobuf::RepeatedPtrField<AssertionRequest>::const_iterator requests_first,
    google::protobuf::RepeatedPtrField<AssertionRequest>::const_iterator requests_last,
    std::string *output) {
  // Generate an ephemeral Diffie-Hellman key-pair for the negotiated cipher
  // suite.
  switch (selected_cipher_suite_) {
    case CURVE25519_SHA256:
      dh_public_key_.resize(X25519_PUBLIC_VALUE_LEN);
      dh_private_key_.resize(X25519_PRIVATE_KEY_LEN);
      X25519_keypair(dh_public_key_.data(), dh_private_key_.data());
      break;
    default:
      LOG(ERROR) << "Client handshaker has bad cipher suite configuration";
      return EkepError(Abort::INTERNAL_ERROR,
                       "Unable to use selected cipher suite");
  }

  ClientId client_id;
  client_id.set_dh_public_key(dh_public_key_.data(), dh_public_key_.size());

  std::string public_key(reinterpret_cast<const char *>(dh_public_key_.data()),
                         dh_public_key_.size());

  // At this stage in the protocol, the transcript is:
  //   hash(ClientPrecommit || ServerPrecommit)
  //
  // The client binds its assertions to this transcript.
  std::string transcript_hash;
  ASYLO_RETURN_IF_ERROR(GetTranscriptHash(&transcript_hash));

  // Each assertion generated by the client is bound to a data blob containing
  // a hash of the current transcript and the client's public key.
  std::string ekep_context;
  if (!MakeEkepContextBlob(public_key, transcript_hash, &ekep_context)) {
    return EkepError(Abort::INTERNAL_ERROR, "Assertion generation failed");
  }

  for (auto it = requests_first; it != requests_last; ++it) {
    const AssertionRequest &request = *it;

    // Note that assertion generators were verified during creation of the
    // handshaker so there is no need to check whether the call to
    // GetEnclaveAssertionGenerator() returns nullptr.
    Status status =
        GetEnclaveAssertionGenerator(request.description())
            ->Generate(ekep_context, request, client_id.add_assertions());
    if (!status.ok()) {
      LOG(ERROR) << "Assertion generation failed: " << status;
      return EkepError(Abort::INTERNAL_ERROR, "Assertion generation failed");
    }
  }

  ASYLO_RETURN_IF_ERROR(
      WriteFrameAndUpdateTranscript(CLIENT_ID, client_id, output));

  // At this stage in the protocol, the transcript is:
  //   hash(ClientPrecommit || ServerPrecommit || ClientId)
  //
  // The server will bind its assertions to this transcript so the client must
  // save a snapshot of the transcript at this time.
  return GetTranscriptHash(&server_assertion_transcript_);
}

Status ClientEkepHandshaker::WriteClientFinish(std::string *output) {
  CleansingVector<uint8_t> handshake_authenticator;
  ASYLO_RETURN_IF_ERROR(ComputeClientHandshakeAuthenticator(
      selected_cipher_suite_, authenticator_secret_, &handshake_authenticator));

  ClientFinish client_finish;
  client_finish.set_handshake_authenticator(handshake_authenticator.data(),
                                            handshake_authenticator.size());

  return WriteFrameAndUpdateTranscript(CLIENT_FINISH, client_finish, output);
}

bool ClientEkepHandshaker::SetSelectedEkepVersion(
    const std::string &ekep_version) {
  // Verify that the selected EKEP version was offered by the client.
  auto version_it = std::find(available_ekep_versions_.cbegin(),
                              available_ekep_versions_.cend(), ekep_version);
  if (version_it == available_ekep_versions_.cend()) {
    return false;
  }

  selected_ekep_version_ = ekep_version;
  return true;
}

bool ClientEkepHandshaker::SetSelectedCipherSuite(
    HandshakeCipher cipher_suite) {
  // Verify that the selected cipher suite was offered by the client.
  auto cipher_it = std::find(available_cipher_suites_.cbegin(),
                             available_cipher_suites_.cend(), cipher_suite);
  if (cipher_it == available_cipher_suites_.cend()) {
    return false;
  }

  selected_cipher_suite_ = cipher_suite;
  return true;
}

bool ClientEkepHandshaker::SetSelectedRecordProtocol(
    RecordProtocol record_protocol) {
  // Verify that the selected record protocol was offered by the client.
  auto protocol_it =
      std::find(available_record_protocols_.cbegin(),
                available_record_protocols_.cend(), record_protocol);
  if (protocol_it == available_record_protocols_.end()) {
    return false;
  }

  selected_record_protocol_ = record_protocol;
  SetRecordProtocol(selected_record_protocol_);
  return true;
}

}  // namespace asylo
