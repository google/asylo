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

#ifndef ASYLO_PLATFORM_HOST_CALL_EXIT_HANDLER_CONSTANTS_H_
#define ASYLO_PLATFORM_HOST_CALL_EXIT_HANDLER_CONSTANTS_H_

#include <cstdint>

#include "asylo/platform/primitives/primitives.h"

namespace asylo {
namespace host_call {

// This file declares the exit points registered by the untrusted code for host
// call handlers. Host call handlers are registered with constants starting from
// |kSelectorHostCall| in increments of 1. The largest handler constant should
// be less than |kSelectorRemote|.

// Exit handler constant for |SystemCallHandler|.
static constexpr uint64_t kSystemCallHandler = primitives::kSelectorHostCall;

// Exit handler constant for |IsAttyHandler|.
static constexpr uint64_t kIsAttyHandler = primitives::kSelectorHostCall + 1;

// Exit handler constant for |USleepHandler|.
static constexpr uint64_t kUSleepHandler = primitives::kSelectorHostCall + 2;

// Exit handler constant for |SysconfHandler|.
static constexpr uint64_t kSysconfHandler = primitives::kSelectorHostCall + 3;

// Exit handler constant for |ReadWithUntrustedPtrHandler|.
static constexpr uint64_t kReadWithUntrustedPtr =
    primitives::kSelectorHostCall + 4;

// Exit handler constant for |ReallocHandler|.
static constexpr uint64_t kReallocHandler = primitives::kSelectorHostCall + 5;

// Exit handler constant for |SleepHandler|.
static constexpr uint64_t kSleepHandler = primitives::kSelectorHostCall + 6;

// Exit handler constant for |SendMsgHandler|.
static constexpr uint64_t kSendMsgHandler = primitives::kSelectorHostCall + 7;

// Exit handler constant for |RecvMsgHandler|.
static constexpr uint64_t kRecvMsgHandler = primitives::kSelectorHostCall + 8;

// Exit handler constant for |GetSocknameHandler|.
static constexpr uint64_t kGetSocknameHandler =
    primitives::kSelectorHostCall + 9;

// Exit handler constant for |AcceptHandler|.
static constexpr uint64_t kAcceptHandler = primitives::kSelectorHostCall + 10;

// Exit handler constant for |GetPeernameHandler|.
static constexpr uint64_t kGetPeernameHandler =
    primitives::kSelectorHostCall + 11;

// Exit handler constant for |RecvfromHandler|.
static constexpr uint64_t kRecvFromHandler = primitives::kSelectorHostCall + 12;

// Exit handler constant for |RaiseHandler|.
static constexpr uint64_t kRaiseHandler = primitives::kSelectorHostCall + 13;

// Exit handler constant for |GetSockOptHandler|.
static constexpr uint64_t kGetSockOptHandler =
    primitives::kSelectorHostCall + 14;

// Exit handler constant for |GetAddrInfoHandler|.
static constexpr uint64_t kGetAddrInfoHandler =
    primitives::kSelectorHostCall + 15;

// Exit handler constant for |InetPtonHandler|.
static constexpr uint64_t kInetPtonHandler = primitives::kSelectorHostCall + 16;

// Exit handler constant for |InetNtopHandler|.
static constexpr uint64_t kInetNtopHandler = primitives::kSelectorHostCall + 17;

// Exit handler constant for |SigprocmaskHandler|.
static constexpr uint64_t kSigprocmaskHandler =
    primitives::kSelectorHostCall + 18;

// Exit handler constant for |IfNameToIndexHandler|.
static constexpr uint64_t kIfNameToIndexHandler =
    primitives::kSelectorHostCall + 19;

// Exit handler constant for |IfNameToIndexHandler|.
static constexpr uint64_t kIfIndexToNameHandler =
    primitives::kSelectorHostCall + 20;

// Exit handler constant for |GetIfAddrsHandler|.
static constexpr uint64_t kGetIfAddrsHandler =
    primitives::kSelectorHostCall + 21;

// Exit handler constant for |GetCpuClockIdHandler|.
static constexpr uint64_t kGetCpuClockIdHandler =
    primitives::kSelectorHostCall + 22;

// Exit handler constant for |GetPwUidHandler|.
static constexpr uint64_t kGetPwUidHandler = primitives::kSelectorHostCall + 23;

// Exit handler constant for |HexDumpHandler|.
static constexpr uint64_t kHexDumpHandler = primitives::kSelectorHostCall + 24;

// Exit handler constant for |OpenLogHandler|.
static constexpr uint64_t kOpenLogHandler = primitives::kSelectorHostCall + 25;

// Exit handler constant for |InotifyReadHandler|.
static constexpr uint64_t kInotifyReadHandler =
    primitives::kSelectorHostCall + 26;

// Exit handler constant for |ClockGettimeHandler|.
static constexpr uint64_t kClockGettimeHandler =
    primitives::kSelectorHostCall + 27;

// Exit handler constant for |SysFutexWaitHandler|.
static constexpr uint64_t kSysFutexWaitHandler =
    primitives::kSelectorHostCall + 28;

// Exit handler constant for |SysFutexWakeHandler|.
static constexpr uint64_t kSysFutexWakeHandler =
    primitives::kSelectorHostCall + 29;

// Exit handler constant for |LocalLifetimeAllocHandler|.
static constexpr uint64_t kLocalLifetimeAllocHandler =
    primitives::kSelectorHostCall + 30;

// Assert that the largest host call handler lies in
// [kSelectorHostCall, kSelectorRemote).
static_assert(kLocalLifetimeAllocHandler < primitives::kSelectorRemote,
              "Cannot have host call handler constant spill over into "
              "|kSelectorRemote|.");

}  // namespace host_call
}  // namespace asylo

#endif  // ASYLO_PLATFORM_HOST_CALL_EXIT_HANDLER_CONSTANTS_H_
