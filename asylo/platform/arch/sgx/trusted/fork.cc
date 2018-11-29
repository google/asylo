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

#include <cstddef>

#include "asylo/util/logging.h"
#include "asylo/platform/arch/include/trusted/enclave_interface.h"
#include "asylo/platform/arch/include/trusted/host_calls.h"
#include "asylo/util/status.h"

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
void SaveThreadLayoutForSnapshot(
    struct ThreadMemoryLayout thread_memory_layout) {
  forked_thread_memory_layout = thread_memory_layout;
}

// Gets the previous saved thread memory layout, including the base address and
// size of the stack/thread info for the TCS that saved the layout.
const struct ThreadMemoryLayout GetThreadLayoutForSnapshot() {
  return forked_thread_memory_layout;
}

}  // namespace

// Takes a snapshot of the enclave data/bss/heap and stack for the calling
// thread by copying to untrusted memory.
Status TakeSnapshotForFork(SnapshotLayout *snapshot_layout) {
#ifndef INSECURE_DEBUG_FORK_ENABLED
  return Status(error::GoogleError::FAILED_PRECONDITION,
                "Insecure fork not enabled");
#endif  // INSECURE_DEBUG_FORK_ENABLED

  LOG(WARNING) << "ENCLAVE FORK IS INSECURE CURRENTLY. THE SNAPSHOT IS "
                  "UNENCRYPTED AND IT LEAKS ALL ENCLAVE DATA!";
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

  // Allocate and copy data section.
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
#ifndef INSECURE_DEBUG_FORK_ENABLED
  return Status(error::GoogleError::FAILED_PRECONDITION,
                "Insecure fork not enabled");
#endif  // INSECURE_DEBUG_FORK_ENABLED

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

}  // namespace asylo
