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

#include <gtest/gtest.h>
#include "asylo/client.h"
#include "asylo/enclave.pb.h"
#include "gflags/gflags.h"
#include "asylo/platform/arch/fork.pb.h"
#include "asylo/platform/common/memory.h"
#include "asylo/platform/core/enclave_manager.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

DEFINE_string(enclave_path, "", "Path to enclave to load");

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
    data_deleter_.Reset(snapshot_layout.data());
    bss_deleter_.Reset(snapshot_layout.bss());
    heap_deleter_.Reset(snapshot_layout.heap());
    thread_deleter_.Reset(snapshot_layout.thread());
    stack_deleter_.Reset(snapshot_layout.stack());
  }

 private:
  SnapshotEntryDeleter data_deleter_;
  SnapshotEntryDeleter bss_deleter_;
  SnapshotEntryDeleter heap_deleter_;
  SnapshotEntryDeleter thread_deleter_;
  SnapshotEntryDeleter stack_deleter_;
};

class ForkSecurityTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    EnclaveManager::Configure(EnclaveManagerOptions());
    StatusOr<EnclaveManager *> manager_result = EnclaveManager::Instance();
    if (!manager_result.ok()) {
      LOG(FATAL) << manager_result.status();
    }
    manager_ = manager_result.ValueOrDie();
  }

  void TearDown() override {
    ASSERT_NE(manager_, nullptr);
    ASSERT_NE(client_, nullptr);
    EnclaveFinal efinal;
    EXPECT_THAT(
        manager_->DestroyEnclave(client_, efinal, /*skip_finalize=*/false),
        IsOk());
  }

  Status LoadEnclaveAndTakeSnapshot(const std::string &enclave_name) {
    SgxLoader loader(FLAGS_enclave_path, /*debug=*/true);
    EnclaveConfig config;
    // Allow a user utility thread for snapshotting and restoring.
    config.set_enable_fork(true);
    ASYLO_RETURN_IF_ERROR(manager_->LoadEnclave(enclave_name, loader, config));

    client_ = reinterpret_cast<SgxClient *>(manager_->GetClient(enclave_name));
    // Enter the enclave and saves the thread and stack address for
    // snapshotting.
    EnclaveInput input;
    ASYLO_RETURN_IF_ERROR(client_->EnterAndRun(input, /*output=*/nullptr));
    // Enter the enclave and take a snapshot of enclave memory.
    ASYLO_RETURN_IF_ERROR(
        manager_->EnterAndTakeSnapshot(client_, &snapshot_layout_));
    snapshot_deleter_.Reset(snapshot_layout_);
    return Status::OkStatus();
  }

  void FlipRandomSnapshotLayoutEntryBit(SnapshotLayoutEntry *entry) {
    uint8_t random_byte_position;
    RAND_bytes(&random_byte_position, sizeof(random_byte_position));
    random_byte_position %= entry->ciphertext_size();
    uint8_t *snapshot_ciphertext =
        reinterpret_cast<uint8_t *>(entry->ciphertext_base());
    snapshot_ciphertext[random_byte_position] ^= 1;
  }

  static EnclaveManager *manager_;
  SgxClient *client_;
  SnapshotLayout snapshot_layout_;
  SnapshotDeleter snapshot_deleter_;
};

EnclaveManager *ForkSecurityTest::manager_ = nullptr;

// Tests that restoring the enclave from its own snapshot succeeds.
TEST_F(ForkSecurityTest, RestoreSucceed) {
  Status status = LoadEnclaveAndTakeSnapshot("Restore succeed");
  if (status.ok()) {
    // SGX hardware mode. Enter the enclave and restore it.
    ASSERT_THAT(manager_->EnterAndRestore(client_, snapshot_layout_), IsOk());
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(error::GoogleError::UNAVAILABLE,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

// Tests that restoring the enclave with data bits modified returns error.
TEST_F(ForkSecurityTest, RestoreWithModifyData) {
  Status status = LoadEnclaveAndTakeSnapshot("Restore with modified data");
  if (status.ok()) {
    // SGX hardware mode. Flip one bit in a random byte in encrypted data
    // section in the snapshot.
    FlipRandomSnapshotLayoutEntryBit(snapshot_layout_.mutable_data());
    // Restoring from modified data section should cause the enclave to return
    // an error.
    ASSERT_THAT(manager_->EnterAndRestore(client_, snapshot_layout_),
                Not(IsOk()));
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(error::GoogleError::UNAVAILABLE,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

// Tests that restoring the enclave with bss bits modified returns error.
TEST_F(ForkSecurityTest, RestoreWithModifyBss) {
  Status status = LoadEnclaveAndTakeSnapshot("Restore with modified bss");
  if (status.ok()) {
    // SGX hardware mode. Flip one bit in a random byte in encrypted bss section
    // in the snapshot.
    FlipRandomSnapshotLayoutEntryBit(snapshot_layout_.mutable_bss());
    // Restoring from modified bss section should cause the enclave to return an
    // error.
    ASSERT_THAT(manager_->EnterAndRestore(client_, snapshot_layout_),
                Not(IsOk()));
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(error::GoogleError::UNAVAILABLE,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

// Tests that restoring the enclave with thread information bits modified
// returns error.
TEST_F(ForkSecurityTest, RestoreWithModifyThread) {
  Status status = LoadEnclaveAndTakeSnapshot("Restore with modified thread");
  if (status.ok()) {
    // SGX hardware mode. Flip one bit in a random byte in encrypted thread
    // information in the snapshot.
    FlipRandomSnapshotLayoutEntryBit(snapshot_layout_.mutable_thread());
    // Restoring from modified thread information should cause the enclave to
    // return an error.
    ASSERT_THAT(manager_->EnterAndRestore(client_, snapshot_layout_),
                Not(IsOk()));
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(error::GoogleError::UNAVAILABLE,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

// Tests that restoring the enclave with stack bits modified returns error.
TEST_F(ForkSecurityTest, RestoreWithModifyStack) {
  Status status = LoadEnclaveAndTakeSnapshot("Restore with modified stack");
  if (status.ok()) {
    // SGX hardware mode. Flip one bit in a random byte in encrypted stack in
    // the snapshot.
    FlipRandomSnapshotLayoutEntryBit(snapshot_layout_.mutable_stack());
    // Restoring from modified stack should cause the enclave to return an
    // error.
    ASSERT_THAT(manager_->EnterAndRestore(client_, snapshot_layout_),
                Not(IsOk()));
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(error::GoogleError::UNAVAILABLE,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

// Tests that restoring the enclave with heap bits modified kills the enclave,
// as the heap is zeroed out when restoring failed.
TEST_F(ForkSecurityTest, RestoreWithModifyHeap) {
  Status status = LoadEnclaveAndTakeSnapshot("Restore with modified heap");
  if (status.ok()) {
    // SGX hardware mode. Flip one bit in a random byte in encrypted heap in the
    // snapshot.
    FlipRandomSnapshotLayoutEntryBit(snapshot_layout_.mutable_heap());
    // Restoring from modified heap should kill the enclave.
    EXPECT_EXIT(manager_->EnterAndRestore(client_, snapshot_layout_),
                ::testing::KilledBySignal(SIGSEGV), ".*");
  } else {
    // No need to do security test for non-hardware mode. Snapshotting/restoring
    // are not supported.
    EXPECT_THAT(status,
                StatusIs(error::GoogleError::UNAVAILABLE,
                         "Secure fork not supported in non SGX hardware mode"));
  }
}

}  // namespace
}  // namespace asylo
