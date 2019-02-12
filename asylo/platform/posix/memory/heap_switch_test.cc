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

#include <stdlib.h>
#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "asylo/platform/arch/include/trusted/enclave_interface.h"
#include "asylo/platform/posix/memory/memory.h"

namespace asylo {
namespace {

bool IsAddressInRange(void *addr, void *base, size_t size) {
  if (!addr) {
    return false;
  }
  size_t start = reinterpret_cast<size_t>(base);
  size_t end = start + size;
  size_t target = reinterpret_cast<size_t>(addr);
  return target >= start && target < end;
}

TEST(HeapSwitchTest, HeapSwitch) {
  struct EnclaveMemoryLayout enclave_memory_layout;
  enc_get_memory_layout(&enclave_memory_layout);

  // Verifies the variable on heap is created on real heap.
  std::unique_ptr<int> variable_on_heap_before_switch =
      absl::make_unique<int>(0);
  EXPECT_TRUE(IsAddressInRange(variable_on_heap_before_switch.get(),
                               enclave_memory_layout.heap_base,
                               enclave_memory_layout.heap_size));

  // Switch heap and verifies the newly heap-allocated variables are on switched
  // heap.
  char switched_heap[8];
  heap_switch(switched_heap, sizeof(switched_heap));
  {
    std::unique_ptr<int> variable_on_heap = absl::make_unique<int>(0);
    EXPECT_TRUE(IsAddressInRange(variable_on_heap.get(), switched_heap,
                                 sizeof(switched_heap)));
  }

  // Switch back to the normal heap and verifies that the newly heap-allocated
  // variables are on real heap.
  heap_switch(nullptr, 0);
  std::unique_ptr<int> variable_on_heap_after_switch =
      absl::make_unique<int>(0);
  EXPECT_TRUE(IsAddressInRange(variable_on_heap_after_switch.get(),
                               enclave_memory_layout.heap_base,
                               enclave_memory_layout.heap_size));
}

}  // namespace
}  // namespace asylo
