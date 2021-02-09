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

#include <stdint.h>
#include <stdlib.h>

#include "include/sgx_cpuid.h"
#include "include/sgx_trts_exception.h"

namespace {

// Handled opcodes
constexpr uint16_t kCpuidOpcode = 0xA20F;
constexpr uint16_t kRdtscOpcode = 0x310F;

// Only support CPUID leaves 0, 1, 4, and 7.
// 0: Vender ID
// 1: Feature information
// 4: Deterministic cache parameters
// 7: Extended features
// This is all that BoringSSL needs to function.
constexpr int kMaxSupportedCpuidLeaf = 7;
constexpr int kSupportedCpuidLeaves[] = {0, 1, 4, 7};

// Holds cached CPUID results.
struct CpuidResult {
  // Indexes into the result array
  enum CpuidRegisters { EAX = 0, EBX = 1, ECX = 2, EDX = 3 };

  // All registers from a CPUID call
  int reg[4];
  bool cached;
};
CpuidResult cpuid_results[kMaxSupportedCpuidLeaf + 1];

// CPUID bits taken from Intel SDM, Vol 2A, CPUID section
constexpr uint32_t CPUID_01H_ECX_SSE3 = 1 << 0;
constexpr uint32_t CPUID_01H_ECX_PCLMULQDQ = 1 << 1;
constexpr uint32_t CPUID_01H_ECX_SSSE3 = 1 << 9;
constexpr uint32_t CPUID_01H_ECX_SSE4_1 = 1 << 19;
constexpr uint32_t CPUID_01H_ECX_SSE4_2 = 1 << 20;
constexpr uint32_t CPUID_01H_ECX_AESNI = 1 << 25;
constexpr uint32_t CPUID_01H_ECX_RDRND = 1 << 30;
constexpr uint32_t CPUID_01H_EDX_SSE = 1 << 25;
constexpr uint32_t CPUID_01H_EDX_SSE2 = 1 << 26;
constexpr uint32_t CPUID_07H_EBX_RDSEED = 1 << 18;

// Prior to any CPUID instructions being executed, go fetch results from outside
// the enclave, for us to use as the results in the enclave.
void initialize_cpuid_results() {
  // Initialize cpuid result array as having no cache results.
  for (int i = 0; i < kMaxSupportedCpuidLeaf; ++i) {
    cpuid_results[i].cached = false;
  }

  // Populate CPUID result cache for each supported leaf.
  for (int i : kSupportedCpuidLeaves) {
    // Get CPUID results from the host and cache the results
    if (sgx_cpuid(cpuid_results[i].reg, i) != SGX_SUCCESS) abort();
    cpuid_results[i].cached = true;
  }


  // Some CPU features are available anywhere that SGX is supported; force
  // particularly security critical ones to true.
  cpuid_results[1].reg[CpuidResult::ECX] |=
      CPUID_01H_ECX_SSE3 | CPUID_01H_ECX_PCLMULQDQ | CPUID_01H_ECX_SSSE3 |
      CPUID_01H_ECX_SSE4_1 | CPUID_01H_ECX_SSE4_2 | CPUID_01H_ECX_AESNI |
      CPUID_01H_ECX_RDRND;
  cpuid_results[1].reg[CpuidResult::EDX] |=
      CPUID_01H_EDX_SSE | CPUID_01H_EDX_SSE2;
  cpuid_results[7].reg[CpuidResult::EBX] |= CPUID_07H_EBX_RDSEED;

}

// Called whenever an SGX exception occurs.  This handler deals with CPUID
// invalid opcode exceptions by filling in data cached earlier.
int handle_cpuid_exception(sgx_exception_info_t *info) {
  // Grab the opcode for the instruction at the exception's instruction pointer.
  uint16_t opcode = *reinterpret_cast<uint16_t *>(info->cpu_context.rip);

  // This handler is only for invalid opcode (#UD) hardware exceptions caused by
  // the CPUID instruction.  For anything else, return indication to keep
  // looking for other possible handlers.
  if (info->exception_vector != SGX_EXCEPTION_VECTOR_UD ||
      info->exception_type != SGX_EXCEPTION_HARDWARE ||
      opcode != kCpuidOpcode) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  // This handler only provides results for CPUID calls that were cached.
  uint64_t leaf = info->cpu_context.rax;
  if (leaf > kMaxSupportedCpuidLeaf || !cpuid_results[leaf].cached) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  // Only subleaf==0 results were cached.  Since subleaf doesn't mean anything
  // for leaves 0 and 1, allow those to be anything (some code doesn't set RCX
  // at all when making those CPUID calls).
  uint64_t subleaf = info->cpu_context.rcx;
  if (leaf != 0 && leaf != 1 && subleaf != 0) return EXCEPTION_CONTINUE_SEARCH;

  // Copy the cached result registers into our result registers.
  info->cpu_context.rax = cpuid_results[leaf].reg[CpuidResult::EAX];
  info->cpu_context.rbx = cpuid_results[leaf].reg[CpuidResult::EBX];
  info->cpu_context.rcx = cpuid_results[leaf].reg[CpuidResult::ECX];
  info->cpu_context.rdx = cpuid_results[leaf].reg[CpuidResult::EDX];

  // CPUID instruction is 2 bytes wide, so advance the instruction pointer
  // beyond it. This way the enclave should continue execution as though the
  // CPUID instruction executed normally.
  info->cpu_context.rip += 2;

  return EXCEPTION_CONTINUE_EXECUTION;
}

// Called whenever an SGX exception occurs.  This handler deals with RDTSC
// invalid opcode exceptions by filling in trivial data.
int handle_rdtsc_exception(sgx_exception_info_t *info) {
  // Grab the opcode for the instruction at the exception's instruction pointer.
  uint16_t opcode = *reinterpret_cast<uint16_t *>(info->cpu_context.rip);

  // This handler is only for invalid opcode (#UD) hardware exceptions caused by
  // the RDTSC instruction.  For anything else, return indication to keep
  // looking for other possible handlers.
  if (info->exception_vector != SGX_EXCEPTION_VECTOR_UD ||
      info->exception_type != SGX_EXCEPTION_HARDWARE ||
      opcode != kRdtscOpcode) {
    return EXCEPTION_CONTINUE_SEARCH;
  }

  // Increment the timestamp value from the last one returned.
  static uint64_t last_rdtsc = 0;
  last_rdtsc++;

  // Split the timestamp and return in registers
  info->cpu_context.rax = last_rdtsc & 0xFFFFFFFF;
  info->cpu_context.rdx = last_rdtsc >> 32;

  // RDTSC instruction is 2 bytes wide, so advance the instruction pointer
  // beyond it. This way the enclave should continue execution should continue
  // as though the CPUID instruction executed normally.
  info->cpu_context.rip += 2;

  return EXCEPTION_CONTINUE_EXECUTION;
}

// Register an exception handler with the SGX SDK.
// Other constructors already issue these instructions, so use the highest
// priority to make this one run first.
void register_exception_handlers() __attribute__((constructor(101)));
void register_exception_handlers() {
  initialize_cpuid_results();
  sgx_register_exception_handler(true, handle_cpuid_exception);
  sgx_register_exception_handler(true, handle_rdtsc_exception);
}

}  // namespace
