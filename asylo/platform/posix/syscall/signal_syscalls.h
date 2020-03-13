/*
 *
 * Copyright 2020 Asylo authors
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

#ifndef ASYLO_PLATFORM_POSIX_SYSCALL_SIGNAL_SYSCALLS_H_
#define ASYLO_PLATFORM_POSIX_SYSCALL_SIGNAL_SYSCALLS_H_

#include <csignal>
#include <cstdlib>

#include "asylo/platform/posix/signal/signal_manager.h"

namespace asylo {

int RtSigaction(int signum, const struct sigaction* act,
                struct sigaction* oldact, size_t sigsetsize);

int RtSigprocmask(int how, const sigset_t* set, sigset_t* oldset,
                  size_t sigsetsize);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_POSIX_SYSCALL_SIGNAL_SYSCALLS_H_
