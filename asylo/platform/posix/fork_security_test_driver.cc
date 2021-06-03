/*
 *
 * Copyright 2019 Asylo authors
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

#include <openssl/rand.h>

#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "asylo/platform/common/memory.h"
#include "asylo/platform/core/enclave_manager.h"
#include "asylo/platform/core/generic_enclave_client.h"
#include "asylo/platform/posix/fork_security_test.pb.h"
#include "asylo/platform/primitives/sgx/fork.pb.h"
#include "asylo/platform/primitives/sgx/loader.pb.h"
#include "asylo/platform/primitives/sgx/untrusted_sgx.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

ABSL_FLAG(std::string, enclave_path, "", "Path to enclave to load");

namespace asylo {
namespace {

using ::testing::Not;

// A helper class that frees the whole snapshot memory.
class SnapshotDeleter {
 public:
  // A helper class to free the memory of a snapshot entry.
  class SnapshotEntryDeleter {
   public:
    SnapshotEntryDeleter()
        : ciphertext_deleter_(nullptr), nonce_deleter_(nullptr) {}

    void Reset(const SnapshotLayoutEntry &entry) {
      ciphertext_deleter_.reset(
          reinterpret_cast<void *>(entry.ciphertext_base()));
      nonce_deleter_.reset(reinterpret_cast<void *>(entry.nonce_base()));
    }

   private:
    MallocUniquePtr<void> ciphertext_deleter_;
    MallocUniquePtr<void> nonce_deleter_;
  };

  void Reset(const SnapshotLayout &snapshot_layout) {
    data_deleter_.resize(snapshot_layout.data_size());
    bss_deleter_.resize(snapshot_layout.bss_size());
    heap_deleter_.resize(snapshot_layout.heap_size());
    thread_deleter_.resize(snapshot_layout.thread_size());
    stack_deleter_.resize(snapshot_layout.stack_size());
    for (int i = 0; i < snapshot_layout.data_size(); ++i) {
      data_deleter_[i].Reset(snapshot_layout.data(i));
    }
    for (int i = 0; i < snapshot_layout.bss_size(); ++i) {
      bss_deleter_[i].Reset(snapshot_layout.bss(i));
    }
    for (int i = 0; i < snapshot_layout.heap_size(); ++i) {
      heap_deleter_[i].Reset(snapshot_layout.heap(i));
    }
    for (int i = 0; i < snapshot_layout.thread_size(); ++i) {
      thread_deleter_[i].Reset(snapshot_layout.thread(i));
    }
    for (int i = 0; i < snapshot_layout.stack_size(); ++i) {
      stack_deleter_[i].Reset(snapshot_layout.stack(i));
    }
  }

 private:
  std::vector<SnapshotEntryDeleter> data_deleter_;
  std::vector<SnapshotEntryDeleter> bss_deleter_;
  std::vector<SnapshotEntryDeleter> heap_deleter_;
  std::vector<SnapshotEntryDeleter> thread_deleter_;
  std::vector<SnapshotEntryDeleter> stack_deleter_;
};

class ForkSecurityTest : public ::testing::Test {
 public:
  ForkSecurityTest()
      : enclave_finalized_(false),
        enclave_crashed_(false),
        wait_thread_inside_(false) {}

 protected:
  static void SetUpTestSuite() {
    EnclaveManager::Configure(EnclaveManagerOptions());
    StatusOr<EnclaveManager *> manager_result = EnclaveManager::Instance();
    if (!manager_result.ok()) {
      LOG(FATAL) << manager_result.status();
    }
    manager_ = manager_result.value();
  }

  void TearDown() override {
    ASSERT_NE(manager_, nullptr);
    ASSERT_NE(client_, nullptr);
    EnclaveFinal efinal;
    // Only finalize the enclave if it's not finalized already by a failed
    // restore.
    if (!enclave_crashed_) {
      EXPECT_THAT(manager_->DestroyEnclave(
                      client_, efinal, /*skip_finalize=*/enclave_finalized_),
                  IsOk());
    }
  }

  Status LoadEnclaveAndTakeSnapshot(const std::string &enclave_name,
                                    bool request_fork) {
    EnclaveConfig config;
    // Allow a user utility thread for snapshotting and restoring.
    config.set_enable_fork(true);

    // Prepare |load_config| message.
    EnclaveLoadConfig load_config;
    load_config.set_name(enclave_name);
    *load_config.mutable_config() = config;
    SgxLoadConfig sgx_config;
    SgxLoadConfig::FileEnclaveConfig file_enclave_config;
    file_enclave_config.set_enclave_path(absl::GetFlag(FLAGS_enclave_path));
    *sgx_config.mutable_file_enclave_config() = file_enclave_config;
    sgx_config.set_debug(true);
    *load_config.MutableExtension(sgx_load_config) = sgx_config;

    // Load Enclave with prepared |EnclaveManager| and |load_config| message.
    ASYLO_RETURN_IF_ERROR(manager_->LoadEnclave(load_config));

    client_ = reinterpret_cast<GenericEnclaveClient *>(
        manager_->GetClient(enclave_name));
    primitive_client_ =
        std::static_pointer_cast<asylo::primitives::SgxEnclaveClient>(
            client_->GetPrimitiveClient());
    // Enter the enclave and saves the thread and stack address for
    // snapshotting.
    EnclaveInput input;
    input.MutableExtension(fork_security_test_input)
        ->set_thread_type(ForkSecurityTestInput::SETREQUEST);
    input.MutableExtension(fork_security_test_input)
        ->set_request_fork(request_fork);
    ASYLO_RETURN_IF_ERROR(client_->EnterAndRun(input, /*output=*/nullptr));

    // Enter the enclave and take a snapshot of enclave memory.
    ASYLO_RETURN_IF_ERROR(
        primitive_client_->EnterAndTakeSnapshot(&snapshot_layout_));
    snapshot_deleter_.Reset(snapshot_layout_);
    return absl::OkStatus();
  }

  // Flip a random bit in the snapshot memory. |entry| stores the layout
  // (address and size) of the snapshot memory.
  void FlipRandomSnapshotLayoutEntryBit(
      const google::protobuf::RepeatedPtrField<SnapshotLayoutEntry> &entry) {
    // Choose a random part to have one bit flipped.
    uint8_t random_index;
    RAND_bytes(&random_index, sizeof(random_index));
    random_index %= entry.size();

    // Choose a random byte in the selected part to have one bit flipped.
    uint8_t random_byte_position;
    RAND_bytes(&random_byte_position, sizeof(random_byte_position));
    random_byte_position %= entry[random_index].ciphertext_size();
    uint8_t *snapshot_ciphertext =
        reinterpret_cast<uint8_t *>(entry[random_index].ciphertext_base());

    // Flip one bit in the selected byte.
    snapshot_ciphertext[random_byte_position] ^= 1;
  }

  static EnclaveManager *manager_;
  GenericEnclaveClient *client_;
  std::shared_ptr<primitives::SgxEnclaveClient> primitive_client_;
  SnapshotLayout snapshot_layout_;
  SnapshotDeleter snapshot_deleter_;
  bool enclave_finalized_;
  bool enclave_crashed_;
  volatile bool wait_thread_inside_;
};

EnclaveManager *ForkSecurityTest::manager_ = nullptr;

// Enters the enclave and stay inside until being notified to exit.
void EnterEnclaveAndWait(GenericEnclaveClient *client,
                         volatile bool *wait_thread_inside) {
  EnclaveInput input;
  input.MutableExtension(fork_security_test_input)
      ->set_thread_type(ForkSecurityTestInput::WAIT);
  input.MutableExtension(fork_security_test_input)
      ->set_wait_thread_inside(reinterpret_cast<uint64_t>(wait_thread_inside));
  client->EnterAndRun(input, /*output=*/nullptr);
}

// Tests that trying to take a snapshot or initialize a key transfer without
// setting the fork requested bit fails.
TEST_F(ForkSecurityTest, SnapshotFailsWithoutForkRequest) {
  Status status =
      LoadEnclaveAndTakeSnapshot("Snapshot blocked", /*request_fork=*/false);
  if (status != Status(absl::StatusCode::kUnavailable,
                       "Secure fork not supported in non SGX hardware mode")) {
    // Snapshot should be rejected without fork request set.
    ASSERT_THAT(status,
                StatusIs(absl::StatusCode::kPermissionDenied,
                         "Snapshot is not allowed unless fork is requested"));

    // Transferring key should be rejected without transfer key request set.
    asylo::ForkHandshakeConfig fork_handshake_config;
    fork_handshake_config.set_is_parent(true);
    fork_handshake_config.set_socket(0);
    EXPECT_THAT(primitive_client_->EnterAndTransferSecureSnapshotKey(
                    fork_handshake_config),
                StatusIs(absl::StatusCode::kPermissionDenied,
                         "Snapshot key transfer is not allowed unless "
                         "requested by fork inside an enclave"));
  }
}

// Tests that restoring the enclave from its own snapshot succeeds.
TEST_F(ForkSecurityTest, RestoreSucceed) {
  Status status =
      LoadEnclaveAndTakeSnapshot("Restore succeed", /*request_fork=*/true);
  if (status.ok()) {
    // SGX hardware mode. Enter the enclave and restore it.
    ASSERT_THAT(primitive_client_->EnterAndRestore(snapshot_layout_), IsOk());
    // Confirms that further calls can enter the enclave after restore
    // succeeded.
    EnclaveInput input;
    input.MutableExtension(fork_security_test_input)
        ->set_thread_type(ForkSecurityTestInput::SETREQUEST);
    input.MutableExtension(fork_security_test_input)->set_request_fork(false);
    EXPECT_THAT(client_->EnterAndRun(input, /*output=*/nullptr), IsOk());
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(absl::StatusCode::kUnavailable,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

// Tests that RestoreEnclave should fail if other threads are running inside the
// enclave.
TEST_F(ForkSecurityTest, RestoreWithOtherThreadsRunning) {
  Status status =
      LoadEnclaveAndTakeSnapshot("Restore with other threads running",
                                 /*request_fork=*/true);
  if (status.ok()) {
    // Confirms that Restore succeeds without other threads running.
    ASSERT_THAT(primitive_client_->EnterAndRestore(snapshot_layout_), IsOk());
    // Create a thread to enter the enclave and busy wait.
    std::thread wait_thread(EnterEnclaveAndWait, client_, &wait_thread_inside_);
    // Wait till the wait thread enters the enclave.
    while (!wait_thread_inside_) {
    }
    // Restore should fail if other threads are running inside the enclave.
    EXPECT_THAT(primitive_client_->EnterAndRestore(snapshot_layout_),
                Not(IsOk()));
    // Set the bit back so that the wait thread will exit.
    wait_thread_inside_ = false;
    wait_thread.join();
    enclave_finalized_ = true;
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(absl::StatusCode::kUnavailable,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

// Tests that restoring the enclave with data bits modified returns error.
TEST_F(ForkSecurityTest, RestoreWithModifyData) {
  Status status = LoadEnclaveAndTakeSnapshot("Restore with modified data",
                                             /*request_fork=*/true);
  if (status.ok()) {
    // SGX hardware mode. Flip one bit in a random byte in encrypted data
    // section in the snapshot.
    FlipRandomSnapshotLayoutEntryBit(snapshot_layout_.data());
    // Restoring from modified data section should cause the enclave to return
    // an error.
    ASSERT_THAT(primitive_client_->EnterAndRestore(snapshot_layout_),
                Not(IsOk()));
    // If restore fails, no further entries should be allowed.
    EnclaveInput input;
    input.MutableExtension(fork_security_test_input)
        ->set_thread_type(ForkSecurityTestInput::SETREQUEST);
    input.MutableExtension(fork_security_test_input)->set_request_fork(false);
    EXPECT_THAT(client_->EnterAndRun(input, /*output=*/nullptr), Not(IsOk()));
    enclave_finalized_ = true;
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(absl::StatusCode::kUnavailable,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

// Tests that restoring the enclave with bss bits modified returns error.
TEST_F(ForkSecurityTest, RestoreWithModifyBss) {
  Status status = LoadEnclaveAndTakeSnapshot("Restore with modified bss",
                                             /*request_fork=*/true);
  if (status.ok()) {
    // SGX hardware mode. Flip one bit in a random byte in encrypted bss section
    // in the snapshot.
    FlipRandomSnapshotLayoutEntryBit(snapshot_layout_.bss());
    // Restoring from modified bss section should cause the enclave to return an
    // error.
    ASSERT_THAT(primitive_client_->EnterAndRestore(snapshot_layout_),
                Not(IsOk()));
    // If restore fails, no further entries should be allowed.
    EnclaveInput input;
    input.MutableExtension(fork_security_test_input)
        ->set_thread_type(ForkSecurityTestInput::SETREQUEST);
    input.MutableExtension(fork_security_test_input)->set_request_fork(false);
    EXPECT_THAT(client_->EnterAndRun(input, /*output=*/nullptr), Not(IsOk()));
    enclave_finalized_ = true;
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(absl::StatusCode::kUnavailable,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

// Tests that restoring the enclave with thread information bits modified
// returns error.
TEST_F(ForkSecurityTest, RestoreWithModifyThread) {
  Status status = LoadEnclaveAndTakeSnapshot("Restore with modified thread",
                                             /*request_fork=*/true);
  if (status.ok()) {
    // SGX hardware mode. Flip one bit in a random byte in encrypted thread
    // information in the snapshot.
    FlipRandomSnapshotLayoutEntryBit(snapshot_layout_.thread());
    // Restoring from modified thread information should cause the enclave to
    // return an error.
    ASSERT_THAT(primitive_client_->EnterAndRestore(snapshot_layout_),
                Not(IsOk()));
    // If restore fails, no further entries should be allowed.
    EnclaveInput input;
    input.MutableExtension(fork_security_test_input)
        ->set_thread_type(ForkSecurityTestInput::SETREQUEST);
    input.MutableExtension(fork_security_test_input)->set_request_fork(false);
    EXPECT_THAT(client_->EnterAndRun(input, /*output=*/nullptr), Not(IsOk()));
    enclave_finalized_ = true;
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(absl::StatusCode::kUnavailable,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

// Tests that restoring the enclave with stack bits modified returns error.
TEST_F(ForkSecurityTest, RestoreWithModifyStack) {
  Status status = LoadEnclaveAndTakeSnapshot("Restore with modified stack",
                                             /*request_fork=*/true);
  if (status.ok()) {
    // SGX hardware mode. Flip one bit in a random byte in encrypted stack in
    // the snapshot.
    FlipRandomSnapshotLayoutEntryBit(snapshot_layout_.stack());
    // Restoring from modified stack should cause the enclave to return an
    // error.
    ASSERT_THAT(primitive_client_->EnterAndRestore(snapshot_layout_),
                Not(IsOk()));
    // If restore fails, no further entries should be allowed.
    EnclaveInput input;
    input.MutableExtension(fork_security_test_input)
        ->set_thread_type(ForkSecurityTestInput::SETREQUEST);
    input.MutableExtension(fork_security_test_input)->set_request_fork(false);
    EXPECT_THAT(client_->EnterAndRun(input, /*output=*/nullptr), Not(IsOk()));
    enclave_finalized_ = true;
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(absl::StatusCode::kUnavailable,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

// Tests that restoring the enclave with heap bits modified kills the enclave,
// as the heap is zeroed out when restoring failed.
TEST_F(ForkSecurityTest, RestoreWithModifyHeap) {
  Status status = LoadEnclaveAndTakeSnapshot("Restore with modified heap",
                                             /*request_fork=*/true);
  if (status.ok()) {
    // SGX hardware mode. Flip one bit in a random byte in encrypted heap in the
    // snapshot.
    FlipRandomSnapshotLayoutEntryBit(snapshot_layout_.heap());
    // Restoring from modified heap should kill the enclave.
    EXPECT_EXIT(primitive_client_->EnterAndRestore(snapshot_layout_),
                ::testing::KilledBySignal(SIGSEGV), ".*");
    enclave_crashed_ = true;
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(absl::StatusCode::kUnavailable,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

}  // namespace
}  // namespace asylo
