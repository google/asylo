/*
 *
 * Copyright 2018 Asylo authors
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

#include "asylo/platform/arch/include/trusted/fork.h"

#include <openssl/rand.h>
#include <sys/socket.h>

#include <cstddef>
#include <vector>

#include "asylo/crypto/aead_cryptor.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/util/logging.h"
#include "asylo/grpc/auth/core/client_ekep_handshaker.h"
#include "asylo/grpc/auth/core/server_ekep_handshaker.h"
#include "asylo/identity/descriptions.h"
#include "asylo/identity/identity_acl_evaluator.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/identity/sgx/self_identity.h"
#include "asylo/identity/sgx/sgx_code_identity_expectation_matcher.h"
#include "asylo/platform/arch/include/trusted/enclave_interface.h"
#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/posix_error_space.h"
#include "asylo/util/status.h"

using AeadCryptor = asylo::experimental::AeadCryptor;

namespace asylo {
namespace {

// Structure describing the layout of per-thread memory resources.
struct ThreadMemoryLayout {
  // Base address of the thread data for the current thread, including the stack
  // guard, stack last pointer etc.
  void *thread_base;
  // Size of the thread data for the current thread.
  size_t thread_size;
  // Base address of the stack for the current thread. This is the upper bound
  // of the stack since stack goes down.
  void *stack_base;
  // Limit address of the stack for the current thread, specifying the last word
  // of the stack. This is the lower bound of the stack since stack goes down.
  void *stack_limit;
};

// Layout of per-thread memory resources for the thread that called fork(). This
// data is saved by the thread that invoked fork(), and copied into the enclave
// snapshot when the reserved fork() implementation thread reenters.
static struct ThreadMemoryLayout forked_thread_memory_layout = {
    nullptr, 0, nullptr, nullptr};

// Saves the thread memory layout, including the base address and size of the
// stack/thread info of the calling TCS.
void SaveThreadLayoutForSnapshot() {
  struct EnclaveMemoryLayout enclave_memory_layout;
  enc_get_memory_layout(&enclave_memory_layout);
  struct ThreadMemoryLayout thread_memory_layout;
  thread_memory_layout.thread_base = enclave_memory_layout.thread_base;
  thread_memory_layout.thread_size = enclave_memory_layout.thread_size;
  thread_memory_layout.stack_base = enclave_memory_layout.stack_base;
  thread_memory_layout.stack_limit = enclave_memory_layout.stack_limit;
  forked_thread_memory_layout = thread_memory_layout;
}

// Gets the previous saved thread memory layout, including the base address and
// size of the stack/thread info for the TCS that saved the layout.
const struct ThreadMemoryLayout GetThreadLayoutForSnapshot() {
  return forked_thread_memory_layout;
}

// Size of snapshot key, which is used to encrypt/decrypt enclave snapshot. We
// use an AES256-GCM-SIV key to encrypt the snapshot.
constexpr size_t kSnapshotKeySize = 32;

// AES256-GCM-SIV snapshot key, which is used to encrypt/decrypt snapshot.
static CleansingVector<uint8_t> *global_snapshot_key;

void DeleteSnapshotKey() {
  if (global_snapshot_key) {
    delete global_snapshot_key;
  }
}

bool SetSnapshotKey(const CleansingVector<uint8_t> &key) {
  if (key.size() != kSnapshotKeySize) {
    return false;
  }
  DeleteSnapshotKey();
  global_snapshot_key = new CleansingVector<uint8_t>(key);
  return true;
}

bool GetSnapshotKey(CleansingVector<uint8_t> *key) {
  if (!global_snapshot_key) {
    return false;
  }
  *key = *global_snapshot_key;
  return true;
}

const char kSnapshotKeyAssociatedDataBuf[] = "AES256-GCM-SIV snapshot key";

}  // namespace

// Takes a snapshot of the enclave data/bss/heap and stack for the calling
// thread by copying to untrusted memory.
Status TakeSnapshotForFork(SnapshotLayout *snapshot_layout) {
  if (!snapshot_layout) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "Snapshot layout is nullptr");
  }

  // Get the information of enclave layout.
  struct EnclaveMemoryLayout enclave_layout;
  enc_get_memory_layout(&enclave_layout);
  if (!enclave_layout.data_base || enclave_layout.data_size <= 0) {
    return Status(error::GoogleError::INTERNAL,
                  "Can't find enclave data section");
  }
  if (!enclave_layout.bss_base || enclave_layout.bss_size <= 0) {
    return Status(error::GoogleError::INTERNAL,
                  "Can't find enclave bss section");
  }
  if (!enclave_layout.heap_base || enclave_layout.heap_size <= 0) {
    return Status(error::GoogleError::INTERNAL, "Can't find enclave heap");
  }

  struct ThreadMemoryLayout thread_layout = GetThreadLayoutForSnapshot();
  if (!thread_layout.thread_base || thread_layout.thread_size <= 0) {
    return Status(error::GoogleError::INTERNAL,
                  "Can't locate the thread calling fork");
  }
  if (!thread_layout.stack_base || !thread_layout.stack_limit) {
    return Status(error::GoogleError::INTERNAL,
                  "Can't locate the stack of the thread calling fork");
  }

  // Generate an AES256-GCM-SIV snapshot key.
  CleansingVector<uint8_t> snapshot_key(kSnapshotKeySize);
  if (!RAND_bytes(snapshot_key.data(), kSnapshotKeySize)) {
    return Status(error::GoogleError::INTERNAL,
                  absl::StrCat("Can not generate the snapshot key: ",
                               BsslLastErrorString()));
  }
  if (!SetSnapshotKey(snapshot_key)) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to save snapshot key inside enclave");
  }

  void *snapshot_data = enc_untrusted_malloc(enclave_layout.data_size);
  if (!snapshot_data) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed allocate untrusted memory for data of the snapshot");
  }
  snapshot_layout->set_data_base(reinterpret_cast<uint64_t>(snapshot_data));
  memcpy(snapshot_data, enclave_layout.data_base, enclave_layout.data_size);
  snapshot_layout->set_data_size(enclave_layout.data_size);

  // Allocate and copy bss section.
  void *snapshot_bss = enc_untrusted_malloc(enclave_layout.bss_size);
  if (!snapshot_bss) {
    return Status(
        error::GoogleError::INTERNAL,
        "Failed to allocate untrusted memory for bss of the snapshot");
  }
  snapshot_layout->set_bss_base(reinterpret_cast<uint64_t>(snapshot_bss));
  memcpy(snapshot_bss, enclave_layout.bss_base, enclave_layout.bss_size);
  snapshot_layout->set_bss_size(enclave_layout.bss_size);

  // Allocate and copy thread data for the calling thread.
  void *snapshot_thread = enc_untrusted_malloc(enclave_layout.thread_size);
  if (!snapshot_thread) {
    return Status(
        error::GoogleError::INTERNAL,
        "Failed to allocate untrusted memory for thread data of the snapshot");
  }
  snapshot_layout->set_thread_base(reinterpret_cast<uint64_t>(snapshot_thread));
  memcpy(snapshot_thread, thread_layout.thread_base, thread_layout.thread_size);
  snapshot_layout->set_thread_size(enclave_layout.thread_size);

  // Allocate and copy heap.
  void *snapshot_heap = enc_untrusted_malloc(enclave_layout.heap_size);
  if (!snapshot_heap) {
    return Status(
        error::GoogleError::INTERNAL,
        "Failed to allocate untrusted memory for heap of the snapshot");
  }
  snapshot_layout->set_heap_base(reinterpret_cast<uint64_t>(snapshot_heap));
  memcpy(snapshot_heap, enclave_layout.heap_base, enclave_layout.heap_size);
  snapshot_layout->set_heap_size(enclave_layout.heap_size);

  // Allocate and copy stack for the calling thread.
  size_t stack_size = reinterpret_cast<size_t>(thread_layout.stack_base) -
                      reinterpret_cast<size_t>(thread_layout.stack_limit);
  void *snapshot_stack = enc_untrusted_malloc(stack_size);
  if (!snapshot_stack) {
    return Status(
        error::GoogleError::INTERNAL,
        "Failed to allocate untrusted memory for stack of the snapshot");
  }
  snapshot_layout->set_stack_base(reinterpret_cast<uint64_t>(snapshot_stack));
  memcpy(snapshot_stack, thread_layout.stack_limit, stack_size);
  snapshot_layout->set_stack_size(stack_size);

  return Status::OkStatus();
}

// Restore the current enclave states from an untrusted snapshot.
Status RestoreForFork(const SnapshotLayout &snapshot_layout) {
  Cleanup delete_snapshot_key(DeleteSnapshotKey);
  // Get the information of current enclave layout.
  struct EnclaveMemoryLayout enclave_layout;
  enc_get_memory_layout(&enclave_layout);
  if (!enclave_layout.data_base ||
      !enc_is_within_enclave(enclave_layout.data_base,
                             snapshot_layout.data_size())) {
    return Status(error::GoogleError::INTERNAL,
                  "enclave data section is not found or unexpected");
  }
  if (!enclave_layout.bss_base ||
      !enc_is_within_enclave(enclave_layout.bss_base,
                             snapshot_layout.bss_size())) {
    return Status(error::GoogleError::INTERNAL,
                  "enclave bss section is not found or unexpected");
  }
  if (!enclave_layout.heap_base ||
      !enc_is_within_enclave(enclave_layout.heap_base,
                             snapshot_layout.heap_size())) {
    return Status(error::GoogleError::INTERNAL,
                  "enclave heap not found or unexpected");
  }

  // Restore data section.
  if (!enc_is_outside_enclave(
          reinterpret_cast<void *>(snapshot_layout.data_base()),
          snapshot_layout.data_size())) {
    return Status(error::GoogleError::INTERNAL,
                  "snapshot data section is not outside the enclave");
  }
  memcpy(enclave_layout.data_base,
         reinterpret_cast<void *>(snapshot_layout.data_base()),
         snapshot_layout.data_size());

  // Restore bss section.
  if (!enc_is_outside_enclave(
          reinterpret_cast<void *>(snapshot_layout.bss_base()),
          snapshot_layout.bss_size())) {
    return Status(error::GoogleError::INTERNAL,
                  "snapshot bss section is not outside the enclave");
  }
  memcpy(enclave_layout.bss_base,
         reinterpret_cast<void *>(snapshot_layout.bss_base()),
         snapshot_layout.bss_size());

  // Restore heap.
  if (!enc_is_outside_enclave(
          reinterpret_cast<void *>(snapshot_layout.heap_base()),
          snapshot_layout.heap_size())) {
    return Status(error::GoogleError::INTERNAL,
                  "snapshot heap is not outside the enclave");
  }
  memcpy(enclave_layout.heap_base,
         reinterpret_cast<void *>(snapshot_layout.heap_base()),
         snapshot_layout.heap_size());

  // Get the information of the thread that calls fork. These are saved in data
  // section, and should be available now since data/bss are restored.
  struct ThreadMemoryLayout thread_layout = GetThreadLayoutForSnapshot();
  if (!thread_layout.thread_base ||
      !enc_is_within_enclave(thread_layout.thread_base,
                             snapshot_layout.thread_size())) {
    return Status(error::GoogleError::INTERNAL,
                  "target tcs thread data not found or unexpected");
  }
  if (!thread_layout.stack_base ||
      !enc_is_within_enclave(thread_layout.stack_limit,
                             snapshot_layout.stack_size())) {
    return Status(error::GoogleError::INTERNAL,
                  "target tcs stack not found or unexpected");
  }

  // Restore thread data for the calling thread.
  if (!enc_is_outside_enclave(
          reinterpret_cast<void *>(snapshot_layout.thread_base()),
          snapshot_layout.thread_size())) {
    return Status(error::GoogleError::INTERNAL,
                  "snapshot thread is not outside the enclave");
  }
  memcpy(thread_layout.thread_base,
         reinterpret_cast<void *>(snapshot_layout.thread_base()),
         snapshot_layout.thread_size());

  // Restore stack for the calling thread.
  if (!enc_is_outside_enclave(
          reinterpret_cast<void *>(snapshot_layout.stack_base()),
          snapshot_layout.stack_size())) {
    return Status(error::GoogleError::INTERNAL,
                  "snapshot stack is not outside the enclave");
  }
  memcpy(thread_layout.stack_limit,
         reinterpret_cast<void *>(snapshot_layout.stack_base()),
         snapshot_layout.stack_size());

  return Status::OkStatus();
}

// Do a full EKEP handshake between the parent and the child enclave.
Status RunEkepHandshake(EkepHandshaker *handshaker, bool is_parent,
                        int socket) {
  std::string outgoing_bytes;

  // Start the handshake.
  EkepHandshaker::Result result = EkepHandshaker::Result::IN_PROGRESS;
  // The parent starts the first step.
  if (is_parent) {
    result = handshaker->NextHandshakeStep(nullptr, 0, &outgoing_bytes);
    if (result == EkepHandshaker::Result::ABORTED) {
      return Status(error::GoogleError::INTERNAL, "EKEP handshake has aborted");
    }

    // The socket is passed directly as a host file descriptor, so call
    // enc_untrusted_write to write to it.
    if (enc_untrusted_write(socket, outgoing_bytes.c_str(),
                            outgoing_bytes.size()) <= 0) {
      return Status(static_cast<error::PosixError>(errno), "Write failed");
    }
  }

  // Loop till the handshake finishes.
  char buf[1024];
  while (result == EkepHandshaker::Result::IN_PROGRESS) {
    do {
      outgoing_bytes.clear();
      // Use MSG_PEEK flag here to read the data without removing it from the
      // receiving queue.
      ssize_t bytes_received =
          enc_untrusted_recvfrom(socket, buf, sizeof(buf), MSG_PEEK,
                                 /*src_addr=*/nullptr, /*addrlen=*/nullptr);
      if (bytes_received <= 0) {
        return Status(static_cast<error::PosixError>(errno), "Read failed");
      }
      result =
          handshaker->NextHandshakeStep(buf, bytes_received, &outgoing_bytes);

      int bytes_used = bytes_received;
      if (result == EkepHandshaker::Result::COMPLETED) {
        // If there are unused bytes left in the handshaker when the handshake
        // is finished, do not remove them from the receiving buffer. They
        // should later be read as the encrypted snapshot key.
        auto unused_bytes_result = handshaker->GetUnusedBytes();
        if (!unused_bytes_result.ok()) {
          return unused_bytes_result.status();
        }
        size_t unused_bytes_size = unused_bytes_result.ValueOrDie().size();
        bytes_used -= unused_bytes_size;
      }
      // Remove the used data from the receiving buffer.
      enc_untrusted_recvfrom(socket, buf, bytes_used, /*flag=*/0,
                             /*src_addr=*/nullptr, /*addrlen=*/nullptr);
    } while (result == EkepHandshaker::Result::NOT_ENOUGH_DATA);

    if (result == EkepHandshaker::Result::ABORTED) {
      return Status(error::GoogleError::INTERNAL, "EKEP handshake has aborted");
    }

    if (result == EkepHandshaker::Result::COMPLETED && !is_parent) {
      // The last step is the child receives the last message from the parent.
      // No need to write to the parent after this step.
      break;
    }

    if (enc_untrusted_write(socket, outgoing_bytes.c_str(),
                            outgoing_bytes.size()) <= 0) {
      return Status(static_cast<error::PosixError>(errno), "Write failed");
    }
  }
  return Status::OkStatus();
}

// Compares the identity of the current enclave with |peer_identity|. In the
// case of fork, the child enclave is loaded in a new process from the same
// binary and in the same virtual address space as the parent enclave.
// Consequently, the identities of the two enclaves should be exactly the same.
Status ComparePeerAndSelfIdentity(const EnclaveIdentity &peer_identity) {
  sgx::CodeIdentityExpectation code_identity_expectation;
  sgx::SetStrictSelfCodeIdentityExpectation(&code_identity_expectation);
  EnclaveIdentityExpectation enclave_identity_expectation;
  ASYLO_RETURN_IF_ERROR(sgx::SerializeSgxExpectation(
      code_identity_expectation, &enclave_identity_expectation));
  IdentityAclPredicate predicate;
  *predicate.mutable_expectation() = enclave_identity_expectation;
  SgxCodeIdentityExpectationMatcher sgx_matcher;

  auto acl_result =
      EvaluateIdentityAcl({peer_identity}, predicate, sgx_matcher);
  if (!acl_result.ok()) {
    return acl_result.status();
  }
  if (!acl_result.ValueOrDie()) {
    return Status(
        error::GoogleError::INTERNAL,
        "The identity of the peer enclave does not match expectation");
  }
  return Status::OkStatus();
}

// Encrypts and transfers snapshot key to the child.
Status EncryptAndSendSnapshotKey(std::unique_ptr<AeadCryptor> cryptor,
                                 int socket) {
  Cleanup delete_snapshot_key(DeleteSnapshotKey);
  CleansingVector<uint8_t> snapshot_key(kSnapshotKeySize);
  if (!GetSnapshotKey(&snapshot_key)) {
    return Status(error::GoogleError::INTERNAL, "Failed to get snapshot key");
  }

  // Encrypts the snapshot key.
  ByteContainerView associated_data(kSnapshotKeyAssociatedDataBuf,
                                    sizeof(kSnapshotKeyAssociatedDataBuf));

  std::vector<uint8_t> snapshot_key_ciphertext(kSnapshotKeySize +
                                               cryptor->MaxSealOverhead());
  std::vector<uint8_t> snapshot_key_nonce(cryptor->NonceSize());
  size_t encrypted_snapshot_key_size;

  ASYLO_RETURN_IF_ERROR(cryptor->Seal(
      snapshot_key, associated_data, absl::MakeSpan(snapshot_key_nonce),
      absl::MakeSpan(snapshot_key_ciphertext), &encrypted_snapshot_key_size));
  snapshot_key_ciphertext.resize(encrypted_snapshot_key_size);

  // Serializes the encrypted snapshot key and the nonce.
  EncryptedSnapshotKey encrypted_snapshot_key;
  encrypted_snapshot_key.set_ciphertext(snapshot_key_ciphertext.data(),
                                        encrypted_snapshot_key_size);
  encrypted_snapshot_key.set_nonce(snapshot_key_nonce.data(),
                                   snapshot_key_nonce.size());

  std::string encrypted_snapshot_key_string;
  if (!encrypted_snapshot_key.SerializeToString(
          &encrypted_snapshot_key_string)) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to serialize EncryptedSnapshotKey");
  }

  // Sends the serialized encrypted snapshot key to the child.
  if (enc_untrusted_write(socket, encrypted_snapshot_key_string.data(),
                          encrypted_snapshot_key_string.size()) <= 0) {
    return Status(static_cast<error::PosixError>(errno), "Write failed");
  }

  return Status::OkStatus();
}

// Receives the snapshot key from the parent, and decrypts the key.
Status ReceiveSnapshotKey(std::unique_ptr<AeadCryptor> cryptor, int socket) {
  // Receives the encrypted snapshot key from the parent.
  char buf[1024];
  int rc = enc_untrusted_read(socket, buf, sizeof(buf));
  if (rc <= 0) {
    return Status(static_cast<error::PosixError>(errno), "Read failed");
  }

  EncryptedSnapshotKey encrypted_snapshot_key;
  if (!encrypted_snapshot_key.ParseFromArray(buf, rc)) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to parse EncryptedSnapshotKey");
  }

  // Decrypts the snapshot key.
  ByteContainerView associated_data(kSnapshotKeyAssociatedDataBuf,
                                    sizeof(kSnapshotKeyAssociatedDataBuf));

  std::vector<uint8_t> snapshot_key_ciphertext(
      encrypted_snapshot_key.ciphertext().cbegin(),
      encrypted_snapshot_key.ciphertext().cend());
  std::vector<uint8_t> snapshot_key_nonce(
      encrypted_snapshot_key.nonce().cbegin(),
      encrypted_snapshot_key.nonce().cend());
  CleansingVector<uint8_t> snapshot_key(snapshot_key_ciphertext.size());
  size_t snapshot_key_size;
  ASYLO_RETURN_IF_ERROR(cryptor->Open(
      snapshot_key_ciphertext, associated_data, snapshot_key_nonce,
      absl::MakeSpan(snapshot_key), &snapshot_key_size));
  snapshot_key.resize(snapshot_key_size);

  // Save the snapshot key inside the enclave for decrypting and restoring the
  // enclave.
  if (!SetSnapshotKey(snapshot_key)) {
    return Status(error::GoogleError::INTERNAL,
                  "Failed to save snapshot key inside enclave");
  }
  return Status::OkStatus();
}

// Securely transfer the snapshot key. First create a shared secret from an EKEP
// handshake between the parent and the child enclave. The parent enclave then
// encrypt the snapshot key with the shared secret, and sends it to the child
// enclave. The chlid enclave then decrypts the key with the shared secret.
Status TransferSecureSnapshotKey(
    const ForkHandshakeConfig &fork_handshake_config) {
  if (!fork_handshake_config.has_is_parent() ||
      !fork_handshake_config.has_socket()) {
    return Status(
        error::GoogleError::INVALID_ARGUMENT,
        "Both the is_parent and socket field should be set for handshake");
  }

  if (fork_handshake_config.socket() < 0) {
    return Status(error::GoogleError::INVALID_ARGUMENT,
                  "The socket field for handshake is invalid");
  }

  AssertionDescription description;
  SetSgxLocalAssertionDescription(&description);

  EkepHandshakerOptions options;
  options.self_assertions.push_back(description);
  options.accepted_peer_assertions.push_back(description);

  // Create an EkepHandshaker based on whether the enclave is parent or child.
  // The parent enclave acts as the client, since the parent enclave will
  // initialize the handshake. The child enclave acts as the server.
  std::unique_ptr<EkepHandshaker> handshaker;
  bool is_parent = fork_handshake_config.is_parent();
  if (is_parent) {
    handshaker = ClientEkepHandshaker::Create(options);
  } else {
    handshaker = ServerEkepHandshaker::Create(options);
  }

  ASYLO_RETURN_IF_ERROR(RunEkepHandshake(handshaker.get(), is_parent,
                                         fork_handshake_config.socket()));

  // Get peer identity from the handshake, and compare it with the identity
  // of the current enclave.
  EnclaveIdentity peer_identity =
      handshaker->GetPeerIdentities().ValueOrDie()->identities(0);

  ASYLO_RETURN_IF_ERROR(ComparePeerAndSelfIdentity(peer_identity));

  // Initialize a cryptor with the AES128-GCM record protocol key from the EKEP
  // handshake.
  CleansingVector<uint8_t> record_protocol_key;
  ASYLO_ASSIGN_OR_RETURN(record_protocol_key,
                         handshaker->GetRecordProtocolKey());
  std::unique_ptr<AeadCryptor> cryptor;
  ASYLO_ASSIGN_OR_RETURN(cryptor,
                         AeadCryptor::CreateAesGcmCryptor(record_protocol_key));

  if (is_parent) {
    return EncryptAndSendSnapshotKey(std::move(cryptor),
                                     fork_handshake_config.socket());
  } else {
    return ReceiveSnapshotKey(std::move(cryptor),
                              fork_handshake_config.socket());
  }
}

pid_t enc_fork(const char *enclave_name, const EnclaveConfig &config) {
  // Saves the current stack/thread address info for snapshot.
  asylo::SaveThreadLayoutForSnapshot();

  std::string buf;
  if (!config.SerializeToString(&buf)) {
    errno = EFAULT;
    return -1;
  }

  return enc_untrusted_fork(enclave_name, buf.data(), buf.size(),
                            /*restore_snapshot=*/true);
}

}  // namespace asylo
