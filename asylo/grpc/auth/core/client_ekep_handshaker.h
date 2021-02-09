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

#ifndef ASYLO_GRPC_AUTH_CORE_CLIENT_EKEP_HANDSHAKER_H_
#define ASYLO_GRPC_AUTH_CORE_CLIENT_EKEP_HANDSHAKER_H_

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

// ClientEkepHandshaker implements the client-specific logic of the EKEP
// handshake. It handles ServerPrecommit, ServerId, and ServerFinish messages
// from the server and sends ClientPrecommit, ClientId, and ClientFinish
// messages to the server.
class ClientEkepHandshaker final : public EkepHandshaker {
 public:
  // Creates a ClientEkepHandshaker configured with the given |options|, if
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
  // Creates a ClientEkepHandshaker configured with the given |options|.
  ClientEkepHandshaker(const EkepHandshakerOptions &options);

  // Validates the ServerPrecommit handshake message contained in |message|. If
  // validation succeeds, writes the ClientId message to |output| and updates
  // the handshake transcript with the outgoing ClientId frame.
  Status HandleServerPrecommit(const google::protobuf::Message &message,
                               std::string *output);

  // Validates the ServerId handshake message contained in |message|.
  Status HandleServerId(const google::protobuf::Message &message);

  // Validates the ServerFinish handshake message contained in |message|. If
  // validation succeeds, writes the ClientFinish message to |output| and
  // updates the handshake transcript with the outgoing ClientFinish frame.
  Status HandleServerFinish(const google::protobuf::Message &message,
                            std::string *output);

  // Writes the ClientPrecommit frame to |output| and updates the transcript.
  Status WriteClientPrecommit(std::string *output);

  // Generates an assertion for each assertion request in the range
  // [|requests_first|, |requests_last|) and adds the resulting assertions to a
  // ClientId frame that is written to |output|. Updates the handshake
  // transcript.
  Status WriteClientId(
      google::protobuf::RepeatedPtrField<AssertionRequest>::const_iterator requests_first,
      google::protobuf::RepeatedPtrField<AssertionRequest>::const_iterator requests_last,
      std::string *output);

  // Writes the ClientFinish frame to |output| and updates the handshake
  // transcript.
  Status WriteClientFinish(std::string *output);

  // Sets the handshaker's selected EKEP version to |ekep_version|. Returns
  // false if |ekep_version| is not a valid EKEP version for this handshaker.
  bool SetSelectedEkepVersion(const std::string &ekep_version);

  // Sets the handshaker's selected cipher suite to |cipher_suite|. Returns
  // false if |cipher_suite| is not a valid cipher suite for this handshaker.
  bool SetSelectedCipherSuite(HandshakeCipher cipher_suite);

  // Sets the handshaker's selected record protocol to |record_protocol|.
  // Returns false if |record_protocol| is not a valid record protocol for this
  // handshaker.
  bool SetSelectedRecordProtocol(RecordProtocol record_protocol);

  // A list of assertions offered by the client.
  const std::vector<AssertionDescription> self_assertions_;

  // A list of peer assertions accepted by the client.
  const std::vector<AssertionDescription> accepted_peer_assertions_;

  // A list of supported cipher suites in order of most preferred to least
  // preferred.
  const std::vector<HandshakeCipher> available_cipher_suites_;

  // A list of supported record protocols in order of most preferred to least
  // preferred.
  const std::vector<RecordProtocol> available_record_protocols_;

  // A list of supported protocol versions in order of most recent to least
  // recent.
  const std::vector<std::string> available_ekep_versions_;

  // Additional data that is authenticated during the handshake.
  const std::string additional_authenticated_data_;

  // Assertions expected from the peer. This field is populated after validation
  // of the ServerPrecommit message.
  std::vector<AssertionDescription> expected_peer_assertions_;

  // The selected cipher suite for the handshake. This field is populated after
  // validation of the ServerPrecommit message.
  HandshakeCipher selected_cipher_suite_;

  // The selected record protocol for securing communication after the
  // handshake. This field is populated after validation of the ServerPrecommit
  // message.
  RecordProtocol selected_record_protocol_;

  // The selected EKEP version for the handshake. This field is populated after
  // validation of the ServerPrecommit message.
  std::string selected_ekep_version_;

  // The client's ephemeral Diffie-Hellman key-pair.
  std::vector<uint8_t> dh_public_key_;
  CleansingVector<uint8_t> dh_private_key_;

  // EKEP Primary and Authenticator secrets.
  CleansingVector<uint8_t> authenticator_secret_;
  CleansingVector<uint8_t> primary_secret_;

  // A snapshot of the transcript to which the server's assertions are bound:
  //   hash(ClientPrecommit || ServerPrecommit || ClientId)
  std::string server_assertion_transcript_;

  // Type of the next message expected by this handshaker.
  HandshakeMessageType expected_message_type_;

  // State of the handshake according to the client.
  EkepHandshaker::HandshakeState handshaker_state_;
};

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_CORE_CLIENT_EKEP_HANDSHAKER_H_
