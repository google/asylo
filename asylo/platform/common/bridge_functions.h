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

#ifndef ASYLO_PLATFORM_COMMON_BRIDGE_FUNCTIONS_H_
#define ASYLO_PLATFORM_COMMON_BRIDGE_FUNCTIONS_H_

#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pwd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <utime.h>

#include <csignal>
#include <cstdint>

#include "asylo/platform/common/bridge_types.h"

namespace asylo {

// Converts |bridge_set| to a runtime signal mask set. Returns nullptr if
// unsuccessful.
sigset_t *FromBridgeSigSet(const bridge_sigset_t *bridge_set, sigset_t *set);

// Converts |set| to a bridge signal mask set. Returns nullptr if unsuccessful.
bridge_sigset_t *ToBridgeSigSet(const sigset_t *set,
                                bridge_sigset_t *bridge_set);

// Converts |bridge_signum| to a runtime signal number. Returns -1 if
// unsuccessful.
int FromBridgeSignal(int bridge_signum);

// Converts |signum| to a bridge signal number. Returns -1 if unsuccessful.
int ToBridgeSignal(int signum);

// Converts |bridge_si_code| to a runtime signal code. Returns -1 if
// unsuccessful.
int FromBridgeSignalCode(int bridge_si_code);

// Converts |si_code| to a bridge signal code. Returns -1 if unsuccessful.
int ToBridgeSignalCode(int si_code);

// Converts |bridge_siginfo| to a runtime siginfo_t. Returns nullptr if
// unsuccessful.
siginfo_t *FromBridgeSigInfo(const struct bridge_siginfo_t *bridge_siginfo,
                             siginfo_t *siginfo);

// Converts |siginfo| to a bridge siginfo_t. Returns nullptr if unsuccessful.
struct bridge_siginfo_t *ToBridgeSigInfo(
    const siginfo_t *siginfo, struct bridge_siginfo_t *bridge_siginfo);

}  // namespace asylo

#endif  // ASYLO_PLATFORM_COMMON_BRIDGE_FUNCTIONS_H_
