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

#include <cstddef>
#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "asylo/platform/posix/memory/memory.h"
#include "asylo/platform/primitives/trusted_runtime.h"

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
  char switched_heap[16];
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

TEST(HeapSwitchTest, MemoryAlignment) {
  char switched_heap[64];
  size_t align = alignof(std::max_align_t);
  heap_switch(switched_heap, sizeof(switched_heap));
  {
    // Verifies that heap-allocation has been switched, and the returned memory
    // address is aligned.
    std::unique_ptr<uint8_t> first_pointer_on_switched_heap =
        absl::make_unique<uint8_t>(0);
    EXPECT_TRUE(IsAddressInRange(first_pointer_on_switched_heap.get(),
                                 switched_heap, sizeof(switched_heap)));
    EXPECT_EQ(
        reinterpret_cast<uintptr_t>(first_pointer_on_switched_heap.get()) %
            align,
        0);

    // Allocates a second time, and verifies that memory allocated is on the
    // switched heap and is aligned.
    std::unique_ptr<uint8_t> second_pointer_on_switched_heap =
        absl::make_unique<uint8_t>(0);
    EXPECT_TRUE(IsAddressInRange(second_pointer_on_switched_heap.get(),
                                 switched_heap, sizeof(switched_heap)));
    EXPECT_EQ(
        reinterpret_cast<uintptr_t>(second_pointer_on_switched_heap.get()) %
            align,
        0);
  }

  // Change the switched heap with an odd shift, and verifies returned memory
  // address is aligned.
  int shift = 29;
  heap_switch(switched_heap + shift, sizeof(switched_heap) - shift);
  {
    std::unique_ptr<uint8_t> pointer_on_shifted_switched_heap =
        absl::make_unique<uint8_t>(0);
    EXPECT_TRUE(IsAddressInRange(pointer_on_shifted_switched_heap.get(),
                                 switched_heap + shift,
                                 sizeof(switched_heap) - shift));
    EXPECT_EQ(
        reinterpret_cast<uintptr_t>(pointer_on_shifted_switched_heap.get()) %
            align,
        0);
  }
  heap_switch(/*address=*/nullptr, /*size=*/0);
}

}  // namespace
}  // namespace asylo
