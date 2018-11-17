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

#include <cstddef>

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
}  // namespace asylo
