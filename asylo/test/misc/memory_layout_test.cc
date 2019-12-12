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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "asylo/platform/primitives/trusted_primitives.h"
#include "asylo/platform/primitives/trusted_runtime.h"

using ::asylo::primitives::TrustedPrimitives;

namespace asylo {
namespace {

int variable_on_data = 1;
int variable_on_bss;

bool IsAddressInRange(void *addr, void *base, size_t size) {
  size_t start = reinterpret_cast<size_t>(base);
  size_t end = start + size;
  size_t target = reinterpret_cast<size_t>(addr);
  return target >= start && target < end;
}

TEST(EnclaveMemoryLayout, MemoryLayout) {
  struct EnclaveMemoryLayout enclave_memory_layout;
  enc_get_memory_layout(&enclave_memory_layout);

  // Check data.
  EXPECT_TRUE(TrustedPrimitives::IsInsideEnclave(
      enclave_memory_layout.data_base, enclave_memory_layout.data_size));
  EXPECT_TRUE(IsAddressInRange(reinterpret_cast<void *>(&variable_on_data),
                               enclave_memory_layout.data_base,
                               enclave_memory_layout.data_size));

  // Check bss.
  EXPECT_TRUE(TrustedPrimitives::IsInsideEnclave(
      enclave_memory_layout.bss_base, enclave_memory_layout.bss_size));
  EXPECT_TRUE(IsAddressInRange(reinterpret_cast<void *>(&variable_on_bss),
                               enclave_memory_layout.bss_base,
                               enclave_memory_layout.bss_size));

  // Check heap.
  EXPECT_TRUE(TrustedPrimitives::IsInsideEnclave(
      enclave_memory_layout.heap_base, enclave_memory_layout.heap_size));
  std::unique_ptr<int> variable_on_heap = absl::make_unique<int>(0);
  EXPECT_TRUE(IsAddressInRange(variable_on_heap.get(),
                               enclave_memory_layout.heap_base,
                               enclave_memory_layout.heap_size));

  // Check stack.
  size_t stack_size =
      reinterpret_cast<size_t>(enclave_memory_layout.stack_base) -
      reinterpret_cast<size_t>(enclave_memory_layout.stack_limit);
  EXPECT_TRUE(TrustedPrimitives::IsInsideEnclave(
      enclave_memory_layout.stack_base, stack_size));
  int variable_on_stack = 0;
  EXPECT_TRUE(IsAddressInRange(&variable_on_stack,
                               enclave_memory_layout.stack_limit, stack_size));

  // Check reserved data.
  EXPECT_TRUE(TrustedPrimitives::IsInsideEnclave(
      enclave_memory_layout.reserved_data_base,
      enclave_memory_layout.reserved_data_size));

  // Check reserved bss.
  EXPECT_TRUE(TrustedPrimitives::IsInsideEnclave(
      enclave_memory_layout.reserved_bss_base,
      enclave_memory_layout.reserved_bss_size));

  // Check reserved heap.
  EXPECT_TRUE(TrustedPrimitives::IsInsideEnclave(
      enclave_memory_layout.reserved_heap_base,
      enclave_memory_layout.reserved_heap_size));
}

}  // namespace
}  // namespace asylo
