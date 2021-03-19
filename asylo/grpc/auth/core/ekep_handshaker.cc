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

#include "asylo/grpc/auth/core/ekep_handshaker.h"

#include <cstdint>
#include <memory>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/hash_interface.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/util/logging.h"
#include "asylo/grpc/auth/core/ekep_crypto.h"
#include "asylo/grpc/auth/core/ekep_errors.h"
#include "asylo/util/proto_enum_util.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace {

// Creates and returns a handshake message of type |message_type|.
std::unique_ptr<google::protobuf::Message> CreateHandshakeMessage(
    HandshakeMessageType message_type) {
  switch (message_type) {
    case CLIENT_PRECOMMIT:
      return absl::make_unique<ClientPrecommit>();
    case SERVER_PRECOMMIT:
      return absl::make_unique<ServerPrecommit>();
    case CLIENT_ID:
      return absl::make_unique<ClientId>();
    case SERVER_ID:
      return absl::make_unique<ServerId>();
    case CLIENT_FINISH:
      return absl::make_unique<ClientFinish>();
    case SERVER_FINISH:
      return absl::make_unique<ServerFinish>();
    case ABORT:
      return absl::make_unique<Abort>();
    default:
      return nullptr;
  }
}

}  // namespace

EkepHandshaker::Result EkepHandshaker::NextHandshakeStep(
    const char *incoming_bytes, size_t incoming_bytes_size,
    std::string *outgoing_bytes) {
  VLOG(2) << "Received " << incoming_bytes_size << " bytes from peer";

  if (IsHandshakeCompleted()) {
    LOG(DFATAL) << "NextHandshakeStep() was called on a handshaker that was "
                << "in COMPLETED state";
    return Result::COMPLETED;
  }
  if (IsHandshakeAborted()) {
    LOG(DFATAL) << "NextHandshakeStep() was called on a handshaker that was "
                << "in ABORTED state";
    return Result::ABORTED;
  }

  outgoing_bytes->clear();

  Result result;
  if (!IsHandshakeInProgress()) {
    if (incoming_bytes_size != 0) {
      // The peer sent bytes before the handshake started.
      AbortHandshake(
          EkepError(Abort::BAD_MESSAGE,
                    "Received bytes from peer before handshake was started"),
          outgoing_bytes);
      return Result::ABORTED;
    }

    result = StartHandshake(outgoing_bytes);
  } else {
    // Process bytes from the peer.
    input_stream_.AddBuffer(incoming_bytes, incoming_bytes_size);

    do {
      result = DecodeAndHandleFrame(outgoing_bytes);
      if (result != Result::IN_PROGRESS) {
        return result;
      }
      // Continue processing data from the peer while there are still leftover
      // bytes from the peer and the handshaker has not encoded a response
      // frame.
    } while (input_stream_.RemainingByteCount() != 0 &&
             outgoing_bytes->empty());
  }

  if (!outgoing_bytes->empty() && input_stream_.RemainingByteCount() != 0) {
    // A handshake step was completed and the handshake is still in progress but
    // there are remaining bytes left over. This is not allowed at any step in
    // the protocol.
    outgoing_bytes->clear();
    AbortHandshake(EkepError(Abort::BAD_MESSAGE, "Received unexpected bytes"),
                   outgoing_bytes);
    return Result::ABORTED;
  }

  return result;
}

Status EkepHandshaker::EncodeFrame(
    HandshakeMessageType message_type, const google::protobuf::Message &handshake_message,
    google::protobuf::io::ZeroCopyOutputStream *output) const {
  google::protobuf::io::CodedOutputStream encoded_frame(output);

  size_t message_size = handshake_message.ByteSizeLong();
  if (message_size > max_frame_size_ ||
      sizeof(message_type) + message_size > max_frame_size_) {
    return EkepError(
        Abort::INTERNAL_ERROR,
        absl::StrCat(
            "Attempting to create frame that exceeds max frame size of ",
            max_frame_size_));
  }

  if (message_type == HandshakeMessageType::UNKNOWN_HANDSHAKE_MESSAGE) {
    return EkepError(
        Abort::INTERNAL_ERROR,
        "Cannot create a frame with message type UNKNOWN_HANDSHAKE_MESSAGE");
  }

  // Write the frame size.
  uint32_t frame_size = sizeof(message_type) + message_size;
  encoded_frame.WriteLittleEndian32(frame_size);

  // Write the message type.
  encoded_frame.WriteLittleEndian32(message_type);

  // Write the serialized message.
  handshake_message.SerializeWithCachedSizes(&encoded_frame);

  return absl::OkStatus();
}

Status EkepHandshaker::ParseFrameHeader(
    google::protobuf::io::ZeroCopyInputStream *input, uint32_t *message_size,
    HandshakeMessageType *message_type) const {
  google::protobuf::io::CodedInputStream encoded_frame(input);

  // Read in the frame size.
  uint32_t frame_size;
  if (!encoded_frame.ReadLittleEndian32(&frame_size)) {
    return EkepError(Abort::BAD_MESSAGE, "Failed to read frame size");
  }
  if (frame_size < sizeof(*message_type) || frame_size > max_frame_size_) {
    return EkepError(Abort::BAD_MESSAGE,
                     absl::StrCat("Invalid frame size: ", frame_size));
  }

  // Read in the message type.
  uint32_t message_type_encoded;
  if (!encoded_frame.ReadLittleEndian32(&message_type_encoded)) {
    return EkepError(Abort::BAD_MESSAGE, "Failed to read frame message type");
  }
  if (!HandshakeMessageType_IsValid(message_type_encoded)) {
    return EkepError(
        Abort::BAD_MESSAGE,
        absl::StrCat("Invalid frame message type: ", message_type_encoded));
  }
  if (message_type_encoded == HandshakeMessageType::UNKNOWN_HANDSHAKE_MESSAGE) {
    return EkepError(Abort::BAD_MESSAGE,
                     "Received frame with UNKNOWN_HANDSHAKE_MESSAGE type");
  }

  *message_type = static_cast<HandshakeMessageType>(message_type_encoded);
  *message_size = frame_size - sizeof(*message_type);
  return absl::OkStatus();
}

Status EkepHandshaker::ParseFrameMessage(uint32_t message_size,
                                         google::protobuf::io::ZeroCopyInputStream *input,
                                         google::protobuf::Message *message) const {
  if (!message->ParseFromBoundedZeroCopyStream(input, message_size)) {
    return EkepError(Abort::DESERIALIZATION_FAILED,
                     "Failed to deserialize handshake message");
  }
  return absl::OkStatus();
}

StatusOr<std::string> EkepHandshaker::GetUnusedBytes() {
  if (!IsHandshakeCompleted()) {
    return Status(::absl::StatusCode::kFailedPrecondition,
                  "Cannot retrieve unused bytes before handshake is complete");
  }

  return input_stream_.RemainingBytes();
}

StatusOr<std::unique_ptr<EnclaveIdentities>>
EkepHandshaker::GetPeerIdentities() {
  if (!IsHandshakeCompleted()) {
    return Status(::absl::StatusCode::kFailedPrecondition,
                  "Cannot retrieve peer identity before handshake is "
                  "complete");
  }

  return std::move(peer_identities_);
}

StatusOr<RecordProtocol> EkepHandshaker::GetRecordProtocol() {
  if (!IsHandshakeCompleted()) {
    return Status(::absl::StatusCode::kFailedPrecondition,
                  "Cannot retrieve record protocol before handshake is "
                  "complete");
  }

  return record_protocol_;
}

StatusOr<CleansingVector<uint8_t>> EkepHandshaker::GetRecordProtocolKey() {
  if (!IsHandshakeCompleted()) {
    return Status(::absl::StatusCode::kFailedPrecondition,
                  "Cannot retrieve record protocol key before handshake is "
                  "complete");
  }

  return record_protocol_key_;
}

EkepHandshaker::EkepHandshaker(int max_frame_size)
    : max_frame_size_(max_frame_size) {
  peer_identities_ = absl::make_unique<EnclaveIdentities>();
}

EkepHandshaker::Result EkepHandshaker::DecodeAndHandleFrame(
    std::string *output) {
  // Check if there are enough bytes to parse a frame header.
  if (input_stream_.RemainingByteCount() < kEkepFrameHeaderSize) {
    return Result::NOT_ENOUGH_DATA;
  }

  // There are enough bytes to parse the frame header. Any errors that occur in
  // header parsing are now fatal.
  uint32_t message_size;
  HandshakeMessageType message_type;
  Status status =
      ParseFrameHeader(&input_stream_, &message_size, &message_type);
  if (!status.ok()) {
    AbortHandshake(status, output);
    return Result::ABORTED;
  }

  VLOG(2) << "Received " << ProtoEnumValueName(message_type) << " from peer";

  if ((message_type != GetExpectedMessageType()) && (message_type != ABORT)) {
    // Don't bother decoding an unexpected message, unless it's an ABORT.
    AbortHandshake(EkepError(Abort::PROTOCOL_ERROR, "Unexpected message"),
                   output);
    return Result::ABORTED;
  }

  if (input_stream_.RemainingByteCount() < message_size) {
    // Not enough bytes to parse the frame message. Rewind the internal stream
    // since the frame was not consumed.
    input_stream_.Rewind();
    return Result::NOT_ENOUGH_DATA;
  }
  std::unique_ptr<google::protobuf::Message> message =
      CreateHandshakeMessage(message_type);

  // There are enough bytes to parse the frame message. Any errors that occur
  // during deserialization are fatal.
  status = ParseFrameMessage(message_size, &input_stream_, message.get());
  if (!status.ok()) {
    if (message_type == ABORT) {
      // The peer sent an Abort message that could not be parsed. There is not
      // much else to do but log the error and stop the handshake.
      HandleAbortMessage(nullptr);
      LOG(ERROR) << "Failed to deserialize peer's Abort: " << status;
    } else {
      AbortHandshake(status, output);
    }
    return Result::ABORTED;
  }

  VLOG(2) << message->DebugString();

  if (message_type == ABORT) {
    const Abort *abort_message = dynamic_cast<const Abort *>(message.get());
    LOG_IF(DFATAL, !abort_message) << "dynamic_cast from google::protobuf::Message * "
                                   << "to Abort * failed";
    HandleAbortMessage(abort_message);
    return Result::ABORTED;
  }

  // Add all consumed bytes to the transcript and expunge them.
  UpdateTranscriptWithIncomingBytes();
  input_stream_.TrimFront();

  return HandleHandshakeMessage(message_type, *message, output);
}

Status EkepHandshaker::WriteFrameAndUpdateTranscript(
    HandshakeMessageType message_type, const google::protobuf::Message &handshake_message,
    std::string *output) {
  int offset = output->size();
  google::protobuf::io::StringOutputStream outgoing_frame(output);
  ASYLO_RETURN_IF_ERROR(
      EncodeFrame(message_type, handshake_message, &outgoing_frame));

  // There may be outgoing frames already written to |output|. Only add bytes
  // from the most recently-written frame to the transcript.
  UpdateTranscriptWithOutgoingBytes(output->data() + offset,
                                    output->size() - offset);
  return absl::OkStatus();
}

void EkepHandshaker::AddPeerIdentity(const EnclaveIdentity &identity) {
  *peer_identities_->add_identities() = identity;
}

void EkepHandshaker::SetRecordProtocol(RecordProtocol record_protocol) {
  record_protocol_ = record_protocol;
}

Status EkepHandshaker::DeriveAndSetRecordProtocolKey(
    HandshakeCipher cipher_suite, RecordProtocol record_protocol,
    ByteContainerView primary_secret) {
  std::string final_transcript_hash;
  ASYLO_RETURN_IF_ERROR(GetTranscriptHash(&final_transcript_hash));
  return DeriveRecordProtocolKey(cipher_suite, record_protocol,
                                 final_transcript_hash, primary_secret,
                                 &record_protocol_key_);
}

bool EkepHandshaker::SetTranscriptHashFunction(HashInterface *hash) {
  return transcript_.SetHasher(hash);
}

Status EkepHandshaker::GetTranscriptHash(std::string *transcript_hash) {
  bool result = transcript_.Hash(transcript_hash);
  if (!result) {
    LOG(ERROR) << "Transcript hash function is not set";
    return EkepError(Abort::INTERNAL_ERROR,
                     "Unable to retrieve transcript hash");
  }
  return absl::OkStatus();
}

void EkepHandshaker::UpdateTranscriptWithOutgoingBytes(
    const char *outgoing_bytes, int outgoing_bytes_size) {
  if (outgoing_bytes_size > 0) {
    google::protobuf::io::ArrayInputStream sent_bytes(outgoing_bytes,
                                            outgoing_bytes_size);
    transcript_.Add(&sent_bytes);
  }
}

void EkepHandshaker::UpdateTranscriptWithIncomingBytes() {
  int64_t bytes_read = input_stream_.ByteCount();
  if (bytes_read != 0) {
    input_stream_.Rewind();
    google::protobuf::io::LimitingInputStream consumed_bytes(&input_stream_, bytes_read);
    transcript_.Add(&consumed_bytes);
  }
}

}  // namespace asylo
