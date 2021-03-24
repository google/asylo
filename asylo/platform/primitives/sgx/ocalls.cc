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

// Stubs invoked by edger8r generated bridge code for ocalls.

// For |domainname| field in pipe2().
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include "absl/status/status.h"
#endif

#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iterator>
#include <vector>

#include "asylo/util/logging.h"
#include "asylo/platform/common/memory.h"
#include "asylo/platform/primitives/sgx/generated_bridge_u.h"
#include "asylo/platform/primitives/sgx/sgx_params.h"
#include "asylo/platform/primitives/sgx/signal_dispatcher.h"
#include "asylo/platform/primitives/sgx/untrusted_sgx.h"
#include "asylo/platform/primitives/untrusted_primitives.h"
#include "asylo/platform/primitives/util/message.h"
#include "asylo/platform/storage/utils/fd_closer.h"
#include "asylo/platform/system_call/type_conversions/types_functions.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h"
#include "QuoteGeneration/quote_wrapper/ql/inc/sgx_dcap_ql_wrapper.h"
#include "QuoteGeneration/quote_wrapper/quote/inc/sgx_ql_core_wrapper.h"

namespace {

// Stores a pointer to a function inside the enclave that translates
// |klinux_signum| to a value inside the enclave and calls the registered signal
// handler for that signal.
static void (*handle_signal_inside_enclave)(int, klinux_siginfo_t *,
                                            void *) = nullptr;

// Calls the function registered as the signal handler inside the enclave.
void TranslateToBridgeAndHandleSignal(int klinux_signum, siginfo_t *info,
                                      void *ucontext) {
  // |info| is handled inside the enclave via the function pointer
  // |handle_signal_inside_enclave|, and therefore needs to have a consistent
  // type inside and outside the enclave. We utilize our definition of
  // klinux_siginfo_t for this purpose, instead of defining a new "bridge" type.
  klinux_siginfo_t klinux_siginfo = {};
  klinux_siginfo.si_signo = info->si_signo;
  klinux_siginfo.si_code = info->si_code;

  if (handle_signal_inside_enclave) {
    handle_signal_inside_enclave(klinux_signum, &klinux_siginfo, ucontext);
  }
}

// Triggers an ecall to enter an enclave to handle the incoming signal.
//
// In hardware mode, this is registered as the signal handler.
// In simulation mode, this is called if the signal arrives when the TCS is
// inactive.
void EnterEnclaveAndHandleSignal(int signum, siginfo_t *info, void *ucontext) {
  asylo::primitives::EnclaveSignalDispatcher::GetInstance()
      ->EnterEnclaveAndHandleSignal(signum, info, ucontext);
}

// Checks the enclave TCS state to determine which function to call to handle
// the signal. If the TCS is active, calls the signal handler registered inside
// the enclave directly. If the TCS is inactive, triggers an ecall to enter
// enclave and handle the signal.
//
// In simulation mode, this is registered as the signal handler.
void HandleSignalInSim(int signum, siginfo_t *info, void *ucontext) {
  asylo::primitives::SgxEnclaveClient *client =
      dynamic_cast<asylo::primitives::SgxEnclaveClient *>(
          asylo::primitives::EnclaveSignalDispatcher::GetInstance()
              ->GetClientForSignal(signum));
  if (!client) {
    return;
  }
  // A thread local variable that is used to decide whether the simulation mode
  // has thread local inside the enclave or on the host. If the thread locals
  // are outside the enclave, we enter the enclave to handle the signal,
  // otherwise invoke the signal handler inside the enclave directly.
  thread_local int test_thread_local = 0;
  uintptr_t thread_local_address =
      reinterpret_cast<uintptr_t>(&test_thread_local);
  uintptr_t enclave_base =
      reinterpret_cast<uintptr_t>(client->GetBaseAddress());
  size_t enclave_size = client->GetEnclaveSize();
  if (thread_local_address >= enclave_base &&
      thread_local_address < enclave_base + enclave_size) {
    TranslateToBridgeAndHandleSignal(signum, info, ucontext);
  } else {
    EnterEnclaveAndHandleSignal(signum, info, ucontext);
  }
}

// Perform a snapshot key transfer from the parent to the child.
asylo::Status DoSnapshotKeyTransfer(int self_socket, int peer_socket,
                                    bool is_parent) {
  asylo::platform::storage::FdCloser self_socket_closer(self_socket);
  // Close the socket for the other side, and enters the enclave to send the
  // snapshot key through the socket.
  if (close(peer_socket) < 0) {
    return asylo::LastPosixError("close failed");
  }

  asylo::ForkHandshakeConfig fork_handshake_config;
  fork_handshake_config.set_is_parent(is_parent);
  fork_handshake_config.set_socket(self_socket);
  auto primitive_client = dynamic_cast<asylo::primitives::SgxEnclaveClient *>(
      asylo::primitives::Client::GetCurrentClient());
  ASYLO_RETURN_IF_ERROR(primitive_client->EnterAndTransferSecureSnapshotKey(
      fork_handshake_config));

  return absl::OkStatus();
}

// A helper class to free the snapshot memory allocated during fork.
class SnapshotDataDeleter {
 public:
  explicit SnapshotDataDeleter(const asylo::SnapshotLayoutEntry &entry)
      : ciphertext_deleter_(reinterpret_cast<void *>(entry.ciphertext_base())),
        nonce_deleter_(reinterpret_cast<void *>(entry.nonce_base())) {}

 private:
  asylo::MallocUniquePtr<void> ciphertext_deleter_;
  asylo::MallocUniquePtr<void> nonce_deleter_;
};

}  // namespace

//////////////////////////////////////
//              IO                  //
//////////////////////////////////////

int ocall_untrusted_debug_puts(const char *str) {
  int rc = puts(str);
  // This routine is intended for debugging, so flush immediately to ensure
  // output is written in the event the enclave aborts with buffered output.
  fflush(stdout);
  return rc;
}

void *ocall_untrusted_local_alloc(uint64_t size) {
  void *ret = malloc(static_cast<size_t>(size));
  return ret;
}

void **ocall_enc_untrusted_allocate_buffers(uint64_t count, uint64_t size) {
  void **buffers = reinterpret_cast<void **>(
      malloc(static_cast<size_t>(count) * sizeof(void *)));
  for (int i = 0; i < count; i++) {
    buffers[i] = malloc(size);
  }
  return buffers;
}

void ocall_enc_untrusted_deallocate_free_list(void **free_list,
                                              uint64_t count) {
  // This function only releases memory on the untrusted heap pointed to by
  // buffer pointers stored in |free_list|, not freeing the |free_list| object
  // itself. The client making the host call is responsible for the deallocation
  // of the |free list| object.
  for (int i = 0; i < count; i++) {
    free(free_list[i]);
  }
}

//////////////////////////////////////
//          signal.h                //
//////////////////////////////////////

int ocall_enc_untrusted_register_signal_handler(int klinux_signum,
                                                void *sigaction_ptr,
                                                const void *klinux_mask,
                                                int klinux_mask_len,
                                                int64_t flags) {
  if (klinux_signum < 0) {
    errno = EINVAL;
    return -1;
  }

  auto primitive_client = dynamic_cast<asylo::primitives::SgxEnclaveClient *>(
      asylo::primitives::Client::GetCurrentClient());
  if (!primitive_client) {
    LOG(ERROR) << "Invalid primitive_client countered.";
    return -1;
  }
  const asylo::primitives::SgxEnclaveClient *old_client =
      asylo::primitives::EnclaveSignalDispatcher::GetInstance()->RegisterSignal(
          klinux_signum, primitive_client);
  if (old_client) {
    LOG(WARNING) << "Overwriting the signal handler for signal: "
                 << klinux_signum << " registered by another enclave";
  }
  struct sigaction newact {};
  if (!sigaction_ptr) {
    // Hardware mode: The registered signal handler triggers an ecall to enter
    // the enclave and handle the signal.
    newact.sa_sigaction = &EnterEnclaveAndHandleSignal;
  } else {
    // Simulation mode: The registered signal handler does the same as hardware
    // mode if the TCS is active, or calls the signal handler registered inside
    // the enclave directly if the TCS is inactive.
    handle_signal_inside_enclave =
        reinterpret_cast<void (*)(int, klinux_siginfo_t *, void *)>(
            sigaction_ptr);
    newact.sa_sigaction = &HandleSignalInSim;
  }

  // Set the flag so that sa_sigaction is registered as the signal handler
  // instead of sa_handler.
  newact.sa_flags = flags;
  newact.sa_flags |= SA_SIGINFO;
  newact.sa_mask = *reinterpret_cast<const sigset_t *>(klinux_mask);

  struct sigaction oldact {};
  return sigaction(klinux_signum, &newact, &oldact);
}

//////////////////////////////////////
//            unistd.h              //
//////////////////////////////////////

void ocall_enc_untrusted__exit(int rc) { _exit(rc); }

int32_t ocall_enc_untrusted_fork(const char *enclave_name,
                                 bool restore_snapshot) {
  auto primitive_client = dynamic_cast<asylo::primitives::SgxEnclaveClient *>(
      asylo::primitives::Client::GetCurrentClient());
  if (!primitive_client) {
    return -1;
  }

  if (!restore_snapshot) {
    // No need to take and restore a snapshot, just set indication that the new
    // enclave is created from fork.
    pid_t pid = fork();
    if (pid == 0) {
      // Set the process ID so that the new enclave created from fork does not
      // reject entry.
      primitive_client->SetProcessId();
    }
    return pid;
  }

  // A snapshot should be taken and restored for fork, take a snapshot of the
  // current enclave memory.
  void *enclave_base_address = primitive_client->GetBaseAddress();
  asylo::SnapshotLayout snapshot_layout;
  asylo::Status status =
      primitive_client->EnterAndTakeSnapshot(&snapshot_layout);
  if (!status.ok()) {
    LOG(ERROR) << "EnterAndTakeSnapshot failed: " << status;
    errno = ENOMEM;
    return -1;
  }

  // The snapshot memory should be freed in both the parent and the child
  // process.
  std::vector<SnapshotDataDeleter> data_deleter_;
  std::vector<SnapshotDataDeleter> bss_deleter_;
  std::vector<SnapshotDataDeleter> heap_deleter_;
  std::vector<SnapshotDataDeleter> thread_deleter_;
  std::vector<SnapshotDataDeleter> stack_deleter_;

  std::transform(snapshot_layout.data().cbegin(), snapshot_layout.data().cend(),
                 std::back_inserter(data_deleter_),
                 [](const asylo::SnapshotLayoutEntry &entry) {
                   return SnapshotDataDeleter(entry);
                 });

  std::transform(snapshot_layout.bss().cbegin(), snapshot_layout.bss().cend(),
                 std::back_inserter(bss_deleter_),
                 [](const asylo::SnapshotLayoutEntry &entry) {
                   return SnapshotDataDeleter(entry);
                 });

  std::transform(snapshot_layout.heap().cbegin(), snapshot_layout.heap().cend(),
                 std::back_inserter(heap_deleter_),
                 [](const asylo::SnapshotLayoutEntry &entry) {
                   return SnapshotDataDeleter(entry);
                 });

  std::transform(snapshot_layout.thread().cbegin(),
                 snapshot_layout.thread().cend(),
                 std::back_inserter(thread_deleter_),
                 [](const asylo::SnapshotLayoutEntry &entry) {
                   return SnapshotDataDeleter(entry);
                 });

  std::transform(snapshot_layout.stack().cbegin(),
                 snapshot_layout.stack().cend(),
                 std::back_inserter(stack_deleter_),
                 [](const asylo::SnapshotLayoutEntry &entry) {
                   return SnapshotDataDeleter(entry);
                 });

  // Create a socket pair used for communication between the parent and child
  // enclave. |socket_pair[0]| is used by the parent enclave and
  // |socket_pair[1]| is used by the child enclave.
  int socket_pair[2];
  if (socketpair(AF_LOCAL, SOCK_STREAM, 0, socket_pair) < 0) {
    LOG(ERROR) << "Failed to create socket pair";
    errno = EFAULT;
    return -1;
  }

  // Create a pipe used to pass the child process fork state to the parent
  // process. If the child process failed to restore the enclave, the parent
  // fork should return error as well.
  int pipefd[2];
  if (pipe(pipefd) < 0) {
    LOG(ERROR) << "Failed to create pipe";
    errno = EFAULT;
    return -1;
  }

  pid_t pid = fork();
  if (pid == -1) {
    return pid;
  }

  if (pid == 0) {
    if (close(pipefd[0]) < 0) {
      LOG(ERROR) << "failed to close pipefd: " << strerror(errno);
      errno = EFAULT;
      return -1;
    }

    auto callback =
        asylo::primitives::SgxEnclaveClient::GetForkedEnclaveLoader();
    if (!callback) {
      LOG(ERROR) << "forked_loader_callback not set.";
      errno = EFAULT;
      return -1;
    }
    auto child_primitive_client =
        dynamic_cast<asylo::primitives::SgxEnclaveClient *>(
            callback(enclave_name, enclave_base_address,
                     primitive_client->GetEnclaveSize()));
    if (!child_primitive_client) {
      // errno should be already set by ForkedEnclaveLoader.
      return -1;
    }

    // Verifies that the new enclave is loaded at the same virtual address space
    // as the parent enclave.
    void *child_enclave_base_address = child_primitive_client->GetBaseAddress();
    if (child_enclave_base_address != enclave_base_address) {
      LOG(ERROR) << "New enclave address: " << child_enclave_base_address
                 << " is different from the parent enclave address: "
                 << enclave_base_address;
      errno = EAGAIN;
      return -1;
    }

    // Sets |current_client_| to the new client pointing to the child enclave,
    // instead of the one to the parent.
    child_primitive_client->SetCurrentClient();

    std::string child_result = "Child fork succeeded";
    status = DoSnapshotKeyTransfer(socket_pair[0], socket_pair[1],
                                   /*is_parent=*/false);
    if (!status.ok()) {
      // Inform the parent process about the failure.
      child_result = "Child DoSnapshotKeyTransfer failed";
      if (write(pipefd[1], child_result.data(), child_result.size()) < 0) {
        LOG(ERROR) << "Failed to write child fork result to: " << pipefd[1]
                   << ", error: " << strerror(errno);
        return -1;
      }
      LOG(ERROR) << "DoSnapshotKeyTransfer failed: " << status;
      errno = EFAULT;
      return -1;
    }

    // Enters the child enclave and restore the enclave memory.
    status = child_primitive_client->EnterAndRestore(snapshot_layout);
    if (!status.ok()) {
      // Inform the parent process about the failure.
      child_result = "Child EnterAndRestore failed";
      if (write(pipefd[1], child_result.data(), child_result.size()) < 0) {
        LOG(ERROR) << "Failed to write child fork result to: " << pipefd[1]
                   << ", error: " << strerror(errno);
        return -1;
      }
      LOG(ERROR) << "EnterAndRestore failed: " << status;
      errno = EAGAIN;
      return -1;
    }
    // Inform the parent that child fork has succeeded.
    if (write(pipefd[1], child_result.data(), child_result.size()) < 0) {
      LOG(ERROR) << "Failed to write child fork result to: " << pipefd[1]
                 << ", error: " << strerror(errno);
      return -1;
    }
  } else {
    if (close(pipefd[1]) < 0) {
      LOG(ERROR) << "Failed to close pipefd: " << strerror(errno);
      errno = EFAULT;
      return -1;
    }
    status = DoSnapshotKeyTransfer(/*self_socket=*/socket_pair[1],
                                   /*peer_socket=*/socket_pair[0],
                                   /*is_parent=*/true);
    if (!status.ok()) {
      LOG(ERROR) << "DoSnapshotKeyTransfer failed: " << status;
      errno = EFAULT;
      return -1;
    }
    // Wait for the information from the child process to confirm whether the
    // child enclave has been successfully restored. Timeout at 5 seconds.
    const int timeout_seconds = 5;
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(pipefd[0], &read_fds);
    struct timeval timeout {};
    timeout.tv_sec = timeout_seconds;
    timeout.tv_usec = 0;
    int wait_result =
        select(/*nfds=*/pipefd[0] + 1, &read_fds, /*writefds=*/nullptr,
               /*exceptfds=*/nullptr, &timeout);
    if (wait_result < 0) {
      LOG(ERROR) << "Error while waiting for child fork result: "
                 << strerror(errno);
      return -1;
    } else if (wait_result == 0) {
      LOG(ERROR) << "Timeout waiting for fork result from the child";
      errno = EFAULT;
      return -1;
    }
    // Child fork result is ready to be read.
    char buf[64];
    int rc = read(pipefd[0], buf, sizeof(buf));
    if (rc <= 0) {
      LOG(ERROR) << "Failed to read child fork result";
      return -1;
    }
    buf[rc] = '\0';
    if (strncmp(buf, "Child fork succeeded", sizeof(buf)) != 0) {
      LOG(ERROR) << buf;
      return -1;
    }
  }
  return pid;
}

int ocall_dispatch_untrusted_call(uint64_t selector, void *buffer) {
  asylo::SgxParams *const sgx_params =
      reinterpret_cast<asylo::SgxParams *>(buffer);
  ::asylo::primitives::MessageReader in;
  if (sgx_params->input) {
    in.Deserialize(sgx_params->input, sgx_params->input_size);
  }
  sgx_params->output_size = 0;
  sgx_params->output = nullptr;
  ::asylo::primitives::MessageWriter out;
  const auto status =
      ::asylo::primitives::Client::ExitCallback(selector, &in, &out);
  if (status.ok()) {
    sgx_params->output_size = out.MessageSize();
    if (sgx_params->output_size > 0) {
      sgx_params->output = malloc(sgx_params->output_size);
      out.Serialize(sgx_params->output);
    }
  }
  return status.error_code();
}

void ocall_untrusted_local_free(void *buffer) { free(buffer); }

uint32_t ocall_enc_untrusted_ql_set_quote_config(const sgx_ql_config_t *config,
                                                 uint32_t cert_data_size,
                                                 const uint8_t *cert_data) {
  sgx_ql_config_t config_copy = *config;
  config_copy.cert_data_size = cert_data_size;
  config_copy.p_cert_data = const_cast<uint8_t *>(cert_data);
  return sgx_ql_set_quote_config(&config_copy);
}

uint32_t ocall_enc_untrusted_qe_get_target_info(
    sgx_target_info_t *qe_target_info) {
  return sgx_qe_get_target_info(qe_target_info);
}

uint32_t ocall_enc_untrusted_qe_get_quote_size(uint32_t *quote_size) {
  return sgx_qe_get_quote_size(quote_size);
}

uint32_t ocall_enc_untrusted_qe_get_quote(const sgx_report_t *app_report,
                                          uint32_t quote_size, uint8_t *quote) {
  return sgx_qe_get_quote(app_report, quote_size, quote);
}
