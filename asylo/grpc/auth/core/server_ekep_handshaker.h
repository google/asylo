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

#ifndef ASYLO_GRPC_AUTH_CORE_SERVER_EKEP_HANDSHAKER_H_
#define ASYLO_GRPC_AUTH_CORE_SERVER_EKEP_HANDSHAKER_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/message.h>
#include "asylo/grpc/auth/core/ekep_handshaker.h"
#include "asylo/grpc/auth/core/ekep_handshaker_util.h"
#include "asylo/util/cleansing_types.h"

namespace asylo {

// ServerEkepHandshaker implements the server-specific logic of the EKEP
// handshake. It handles ClientPrecommit, ClientId, and ClientFinish messages
// from the client and sends ServerPrecommit, ServerId, and ServerFinish
// messages to the client.
class ServerEkepHandshaker final : public EkepHandshaker {
 public:
  // Creates a ServerEkepHandshaker configured with the given |options|, if
  // valid. For restrictions on |options|, see the comment for
  // EkepHandshakerOptions::Validate().
  static std::unique_ptr<EkepHandshaker> Create(
      const EkepHandshakerOptions &options);

 protected:
  // From EkepHandshaker interface.
  bool IsHandshakeInProgress() const override;

  // From EkepHandshaker interface.
  bool IsHandshakeCompleted() const override;

  // From EkepHandshaker interface.
  bool IsHandshakeAborted() const override;

  // From EkepHandshaker interface.
  HandshakeMessageType GetExpectedMessageType() const override;

  // From EkepHandshaker interface.
  Result StartHandshake(std::string *output) override;

  // From EkepHandshaker interface.
  void AbortHandshake(const Status &abort_status, std::string *output) override;

  // From EkepHandshaker interface.
  Result HandleHandshakeMessage(HandshakeMessageType message_type,
                                const google::protobuf::Message &handshake_message,
                                std::string *output) override;

  // From EkepHandshaker interface.
  void HandleAbortMessage(const Abort *abort_message) override;

 private:
  // Creates a ServerEkepHandshaker configured with the given |options|.
  ServerEkepHandshaker(const EkepHandshakerOptions &options);

  // Validates the ClientPrecommit handshake message contained in |message|. If
  // validation succeeds, writes the ServerPrecommit message to |output| and
  // updates the handshake transcript with the outgoing ServerPrecommit frame.
  Status HandleClientPrecommit(const google::protobuf::Message &message,
                               std::string *output);

  // Validates the ClientId handshake message contained in |message|. If
  // validation succeeds, writes the ServerId and ServerFinish messages to
  // |output| and updates the handshake transcript with both outgoing frames.
  Status HandleClientId(const google::protobuf::Message &message, std::string *output);

  // Validates the ClientFinish handshake message contained in |message|.
  Status HandleClientFinish(const google::protobuf::Message &message);

  // Writes the ServerPrecommit frame to |output| and updates the handshake
  // transcript.
  Status WriteServerPrecommit(std::string *output);

  // Writes the ServerId frame to |output| and updates the handshake transcript.
  Status WriteServerId(std::string *output);

  // Writes the ServerFinish frame to |output| and updates the handshake
  // transcript.
  Status WriteServerFinish(std::string *output);

  // Sets the handshaker's selected EKEP version to first compatible EKEP
  // version in |ekep_versions|. Returns false if there is no compatible EKEP
  // version in |ekep_versions|.
  bool SetSelectedEkepVersion(
      const google::protobuf::RepeatedPtrField<EkepVersion> &ekep_versions);

  // Sets the handshaker's selected cipher suite to first compatible cipher
  // suite in |cipher_suites|. Returns false if there is no compatible cipher
  // suite in |cipher_suites|.
  bool SetSelectedCipherSuite(const google::protobuf::RepeatedField<int> &cipher_suites);

  // Sets the handshaker's selected record protocol to the first compatible
  // record protocol in |record_protocols|. Returns false if there is no
  // compatible valid record protocol in |record_protocols|.
  bool SetSelectedRecordProtocol(
      const google::protobuf::RepeatedField<int> &record_protocols);

  // A list of assertions offered by the server.
  const std::vector<AssertionDescription> self_assertions_;

  // A list of peer assertions accepted by the server.
  const std::vector<AssertionDescription> accepted_peer_assertions_;

  // A list of supported cipher_suites.
  const std::vector<HandshakeCipher> available_cipher_suites_;

  // A list of supported record protocols.
  const std::vector<RecordProtocol> available_record_protocols_;

  // A list of supported protocol versions in order of most recent to least
  // recent.
  const std::vector<std::string> available_ekep_versions_;

  // Additional data that is authenticated during the handshake.
  const std::string additional_authenticated_data_;

  // Assertions requested by the client that the server is willing to offer.
  // This field is populated after validation of the ClientPrecommit message.
  std::vector<AssertionRequest> promised_assertions_;

  // Assertions expected from the peer. This field is populated after validation
  // of the ClientPrecommit message.
  std::vector<AssertionDescription> expected_peer_assertions_;

  // The selected cipher suite for the handshake. This field is populated after
  // validation of the ClientPrecommit message.
  HandshakeCipher selected_cipher_suite_;

  // The selected record protocol for securing communication after the handshake
  // completes. This field is populated after validation of the ClientPrecommit
  // message.
  RecordProtocol selected_record_protocol_;

  // The selected EKEP version for the handshake. This field is populated after
  // validation of the ClientPrecommit message.
  std::string selected_ekep_version_;

  // The server's ephemeral Diffie-Hellman key-pair.
  std::vector<uint8_t> dh_public_key_;
  CleansingVector<uint8_t> dh_private_key_;

  // The client's Diffie-Hellman public key. This field is populated after
  // validation of the ClientId message.
  std::vector<uint8_t> client_public_key_;

  // EKEP Primary and Authenticator secrets.
  CleansingVector<uint8_t> primary_secret_;
  CleansingVector<uint8_t> authenticator_secret_;

  // A snapshot of the transcript to which the client's assertions are bound:
  //   hash(ClientPrecommit || ServerPrecommit)
  std::string client_assertion_transcript_;

  // Type of the next message expected by this handshaker.
  HandshakeMessageType expected_message_type_;

  // State of the handshake according to the server.
  EkepHandshaker::HandshakeState handshaker_state_;
};

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_CORE_SERVER_EKEP_HANDSHAKER_H_
