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

#ifndef ASYLO_GRPC_AUTH_CORE_EKEP_HANDSHAKER_H_
#define ASYLO_GRPC_AUTH_CORE_EKEP_HANDSHAKER_H_

#include <cstdint>

#include <google/protobuf/io/zero_copy_stream.h>
#include <google/protobuf/message.h>
#include "asylo/crypto/hash_interface.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/grpc/auth/core/transcript.h"
#include "asylo/grpc/auth/util/multi_buffer_input_stream.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

// The size of an EKEP frame header.
constexpr uint32_t kEkepFrameHeaderSize = 8;
constexpr uint32_t kEkepChallengeSize = 32;

// EkepHandshaker is an abstract class that implements the Enclave Key Exchange
// Protocol (EKEP) handshake. EkepHandshaker provides a single entry point,
// NextHandshakeStep(), which performs the next step (or the first step) in the
// handshake. The baseline EkepHandshaker functionality handles frame parsing,
// buffering of frames from the peer, and maintaining the handshake transcript;
// but otherwise does not keep track of any state related to the ongoing
// handshake.
//
// EkepHandshaker exposes virtual methods to be implemented by client and server
// handshaker subclasses. This includes methods that query the current
// handshaker state as well as methods to handle incoming and outgoing frames.
// Handshake-specific state must be managed by the underlying handshaker
// subclass.
//
// EkepHandshaker has two subclasses, ClientEkepHandshaker and
// ServerEkepHandshaker, which implement the client-specific and server-specific
// handshaker functionality, respectively. These classes interoperate to perform
// a complete EKEP handshake.
//
// Note that while all mutable handshake state must be implemented by a
// subclass, the EkepHandshaker class itself maintains a running hash of the
// handshake transcript. Subclasses may call SetTranscriptHashFunction() to set
// the transcript hash function and may call GetTranscriptHash() to get the
// current transcript hash. The EkepHandshaker class is responsible for adding
// incoming frame bytes to the transcript. However, subclasses are responsible
// for adding outgoing frame bytes to the transcript. This is because the
// EkepHandshaker only streams the outgoing bytes and has no knowledge of the
// outgoing frames written by a handshaker. The WriteFrameAndUpdateTranscript()
// method is provided by EkepHandshaker for the purpose of simultaneously
// writing a frame and updating the transcript.
class EkepHandshaker {
 public:
  // Result of handshake step.
  enum class Result {
    NOT_ENOUGH_DATA = 0,
    IN_PROGRESS = 1,
    COMPLETED = 2,
    ABORTED = 3,
  };

  // The limit for maximum frame size for an EkepHandshaker. This constraint is
  // not imposed by EKEP itself. It is a reasonable limit imposed by this EKEP
  // implementation to prevent a badly-behaving EKEP peer from performing a DoS
  // attack on an EkepHandshaker.
  static constexpr size_t kFrameSizeLimit = 1 << 30;  // 1 GB

  virtual ~EkepHandshaker() = default;

  // Performs the next handshake step for this handshaker. This step processes a
  // frame from the peer using |incoming_bytes| and any cached bytes. If a
  // response frame is required to complete the handshake step, attempts to
  // write an outgoing frame to |outgoing_bytes|. The caller must check for the
  // presence of an outgoing frame by checking whether |outgoing_bytes| has a
  // non-zero size.
  //
  // |incoming_bytes| contains |incoming_bytes_size| bytes from the peer.
  // |outgoing_bytes| is an output parameter that contains an outgoing frame, if
  // applicable. If there is no outgoing frame, |outgoing_bytes| is set to an
  // empty string.
  //
  // If a handshake step was completed successfully without completing the
  // handshake, returns IN_PROGRESS.
  // If the handshake was completed successfully, returns COMPLETED.
  // If there are not enough bytes to decode the next frame, returns
  // NOT_ENOUGH_DATA.
  // If the handshake was aborted, returns ABORTED. In this case,
  // |outgoing_bytes| may contain an Abort frame to send to the peer.
  Result NextHandshakeStep(const char *incoming_bytes,
                           size_t incoming_bytes_size,
                           std::string *outgoing_bytes);

  // Encodes |handshake_message| into an EKEP frame and writes the encoded frame
  // to the |output| stream. |message_type| indicates the message type of
  // |handshake_message|. On failure, returns a status with an INTERNAL_ERROR
  // error code.
  Status EncodeFrame(HandshakeMessageType message_type,
                     const google::protobuf::Message &handshake_message,
                     google::protobuf::io::ZeroCopyOutputStream *output) const;

  // Parses an EKEP frame header from the |input| stream. On success, sets
  // |message_size| to the message size computed from the header and sets
  // |message_type| to the message type parsed from the header. On parsing
  // failure, returns a status with a BAD_MESSAGE error code.
  Status ParseFrameHeader(google::protobuf::io::ZeroCopyInputStream *input,
                          uint32_t *message_size,
                          HandshakeMessageType *message_type) const;

  // Parses a handshake message of length |message_size| from the EKEP frame in
  // the |input| stream. |message| should be a valid handshake message proto. On
  // success, initializes |message| to the deserialized handshake message. On
  // parsing failure, returns a status with a DESERIALIZATION_FAILED error code.
  Status ParseFrameMessage(uint32_t message_size,
                           google::protobuf::io::ZeroCopyInputStream *input,
                           google::protobuf::Message *message) const;

  // Returns a string containing the unused bytes at the end of the handshake,
  // given that the handshake has successfully completed. If the handshake has
  // not yet completed, returns GoogleError::FAILED_PRECONDITION.
  StatusOr<std::string> GetUnusedBytes();

  // Returns the peer's identities, given that the handshake has successfully
  // completed. If the handshake has not yet completed, returns
  // GoogleError::FAILED_PRECONDITION.
  StatusOr<std::unique_ptr<EnclaveIdentities>> GetPeerIdentities();

  // Returns the negotiated record protocol, given that the handshake has
  // successfully completed. If the handshake has not yet completed, returns
  // GoogleError::FAILED_PRECONDITION.
  StatusOr<RecordProtocol> GetRecordProtocol();

  // Returns the record protocol key, given that the handshake has successfully
  // completed. If the handshake has not yet completed, returns
  // GoogleError::FAILED_PRECONDITION.
  StatusOr<CleansingVector<uint8_t>> GetRecordProtocolKey();

 protected:
  enum class HandshakeState {
    NOT_STARTED = 0,
    IN_PROGRESS = 1,
    COMPLETED = 2,
    ABORTED = 3,
  };

  EkepHandshaker(int max_frame_size);

  // Attempts to decode and handle a handshake message from the internal
  // input_stream_. Writes any response frames, if applicable, to |output| and
  // returns a Result indicating the status of the handshake.
  Result DecodeAndHandleFrame(std::string *output);

  // Encodes the |handshake_message| of type |message_type| as an EKEP frame,
  // writes the encoded frame to |output|, and updates the transcript with all
  // bytes written to |output|.
  //
  // This method is provided for simultaneously writing outgoing frames and
  // updating the handshake transcript. Note that while the EkepHandshaker base
  // class adds all incoming frame bytes to the transcript, EkepHandshaker
  // implementations are responsible for adding outgoing frame bytes to the
  // transcript.
  //
  // If there is an error encoding the handshake message, returns
  // INTERNAL_ERROR. The returned status object is suitable for passing to
  // AbortHandshake().
  Status WriteFrameAndUpdateTranscript(HandshakeMessageType message_type,
                                       const google::protobuf::Message &handshake_message,
                                       std::string *output);

  // Sets the transcript hash function for this handshaker.
  bool SetTranscriptHashFunction(HashInterface *hash);

  // Returns the current transcript hash for this handshaker.
  //
  // If the transcript hash function has not been set, returns INTERNAL_ERROR.
  // The returned status object is suitable for passing to AbortHandshake().
  Status GetTranscriptHash(std::string *transcript_hash);

  // Adds an identity to the list of peer identities.
  void AddPeerIdentity(const EnclaveIdentity &identity);

  // Sets the record protocol to use after the handshake completes.
  void SetRecordProtocol(RecordProtocol record_protocol);

  // Derives and sets the record protocol key using the given |cipher_suite|,
  // |record_protocol|, |primary_secret|, and the current handshake transcript.
  Status DeriveAndSetRecordProtocolKey(HandshakeCipher cipher_suite,
                                       RecordProtocol record_protocol,
                                       ByteContainerView primary_secret);

  // Returns true if the handshake is in progress. A handshake is in progress if
  // the ClientPrecommit message has been sent and the handshake is neither
  // completed nor aborted.
  virtual bool IsHandshakeInProgress() const = 0;

  // Returns true if the handshake has been completed.
  virtual bool IsHandshakeCompleted() const = 0;

  // Returns true if the handshake has been aborted.
  virtual bool IsHandshakeAborted() const = 0;

  // Returns the type of the next handshake message expected by the handshaker.
  // Returns UNKNOWN_MESSAGE_TYPE if the handshake is not in progress.
  virtual HandshakeMessageType GetExpectedMessageType() const = 0;

  // Starts the handshake by writing the first handshake message to |output|.
  // Returns a Result indicating the status of the handshake.
  //
  // Note that this method is only called if IsHandshakeInProgress() returns
  // false. A client handshaker is responsible for starting the handshake and,
  // consequently, it must provide a meaningful implementation of this method.
  // A server handshaker, on the other hand, can treat this as a no-op.
  virtual Result StartHandshake(std::string *output) = 0;

  // Attempts to write an Abort frame corresponding to |abort_status| to
  // |output| and terminates the handshake. Any further calls to
  // NextHandshakeMessage(), StartHandshake(), or HandleHandshakeMessage() will
  // return ABORTED. If the handshake has already been aborted this method has
  // no effect.
  virtual void AbortHandshake(const Status &abort_status,
                              std::string *output) = 0;

  // Handles the incoming |handshake_message| of type |message_type|, writes any
  // response frames to |output|, and returns a result indicating the state of
  // the handshake. The incoming |message_type| is guaranteed not to be the
  // ABORT message type and |handshake_message| is guaranteed to be an instance
  // of the handshake message proto corresponding to |message_type|. If an error
  // is encountered, attempts to write an Abort message specifying the error
  // that occurred may be written to |output| and returns ABORTED.
  virtual Result HandleHandshakeMessage(
      HandshakeMessageType message_type,
      const google::protobuf::Message &handshake_message, std::string *output) = 0;

  // Handles the specified |abort_message| from the peer by logging details of
  // the abort and terminating the handshake. |abort_message| may be set to
  // nullptr if an Abort message was received from the peer but could not be
  // parsed. After calling this method, any further calls to
  // NextHandshakeMessage(), StartHandshake(), or HandleHandshakeMessage() will
  // return ABORTED.
  virtual void HandleAbortMessage(const Abort *abort_message) = 0;

 private:
  // Updates the transcript with |outgoing_bytes_size| bytes from
  // |outgoing_bytes|.
  void UpdateTranscriptWithOutgoingBytes(const char *outgoing_bytes,
                                         int outgoing_bytes_size);

  // Updates the transcript with all consumed bytes from the internal
  // input_stream_.
  void UpdateTranscriptWithIncomingBytes();

  // The maximum frame size of frames that are encoded and decoded by this
  // handshaker.
  const int max_frame_size_;

  // A stream of unconsumed handshake bytes.
  MultiBufferInputStream input_stream_;

  // A running hash of the handshake transcript.
  Transcript transcript_;

  // The peer's enclave identities.
  std::unique_ptr<EnclaveIdentities> peer_identities_;

  // The record protocol to use to secure the session.
  RecordProtocol record_protocol_;

  // The key used in the record protocol.
  CleansingVector<uint8_t> record_protocol_key_;
};

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_CORE_EKEP_HANDSHAKER_H_
