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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_MOCKS_MOCK_PROC_SYSTEM_PARSER_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_MOCKS_MOCK_PROC_SYSTEM_PARSER_H_

#include <string>

#include <gmock/gmock.h>
#include "absl/strings/str_cat.h"
#include "asylo/platform/primitives/remote/metrics/proc_system_parser.h"

namespace asylo {
namespace primitives {

class MockProcSystemParser : public ProcSystemParser {
 public:
  MockProcSystemParser() : stat_contents_(ComposeStatContents()) {}

  MOCK_METHOD(StatusOr<std::string>, ReadProcStat, (pid_t pid),
              (const, override));

  const int64_t kExpectedPid = 12681;
  const std::string kExpectedComm = "(( foo_bar_))";
  const std::string kExpectedState = "S";
  const int64_t kExpectedPpid = 1;
  const int64_t kExpectedPgrp = 12680;
  const int64_t kExpectedSession = 12680;
  const int64_t kExpectedTtyNr = 0;
  const int64_t kExpectedTpgid = -1;
  const uint64_t kExpectedFlags = 4194304;
  const uint64_t kExpectedMinFlt = 729;
  const uint64_t kExpectedCMinFlt = 0;
  const uint64_t kExpectedMajFlt = 0;
  const uint64_t kExpectedCMajFlt = 0;
  const uint64_t kExpectedUTime = 12898;
  const uint64_t kExpectedSTime = 1045;
  const int64_t kExpectedCUTime = 0;
  const int64_t kExpectedCSTime = 0;
  const uint64_t kExpectedPriority = 20;
  const int64_t kExpectedNice = 0;
  const int64_t kExpectedNumThreads = 1;
  const int64_t kExpectedItRealValue = 0;
  const uint64_t kExpectedStartTime = 9311;
  const uint64_t kExpectedVSize = 109359104;
  const int64_t kExpectedRss = 2407;
  const uint64_t kExpectedRssSLim = 184467440737;
  const uint64_t kExpectedStartCode = 93994270810112;
  const uint64_t kExpectedEndCode = 93994270902144;
  const uint64_t kExpectedStartStack = 140722615139120;
  const uint64_t kExpectedKstKEsp = 0;
  const uint64_t kExpectedKstKEip = 0;
  const uint64_t kExpectedSignal = 0;
  const uint64_t kExpectedBlocked = 0;
  const uint64_t kExpectedSigIgnore = 0;
  const uint64_t kExpectedSigCatch = 81923;
  const uint64_t kExpectedWChan = 1;
  const uint64_t kExpectedNSwap = 0;
  const uint64_t kExpectedCNSwap = 0;
  const int64_t kExpectedExitSignal = 17;
  const int64_t kExpectedProcessor = 5;
  const uint64_t kExpectedRtPriority = 0;
  const uint64_t kExpectedPolicy = 0;
  const uint64_t kExpectedDelayAcctBlkioTicks = 0;
  const uint64_t kExpectedGuestTime = 0;
  const int64_t kExpectedCguestTime = 0;
  const uint64_t kExpectedStartData = 93994273003240;
  const uint64_t kExpectedEndData = 93994273006576;
  const uint64_t kExpectedStartBrk = 93994296090624;
  const uint64_t kExpectedArgStart = 140722615147418;
  const uint64_t kExpectedArgEnd = 140722615147484;
  const uint64_t kExpectedEnvStart = 140722615147484;
  const uint64_t kExpectedEnvEnd = 140722615148521;
  const int64_t kExpectedExitCode = 0;

  const std::string &stat_contents() const { return stat_contents_; }

 private:
  std::string ComposeStatContents() const {
    std::string value;
    absl::StrAppend(&value, kExpectedPid, " ");
    absl::StrAppend(&value, kExpectedComm, " ");
    absl::StrAppend(&value, kExpectedState, " ");
    absl::StrAppend(&value, kExpectedPpid, " ");
    absl::StrAppend(&value, kExpectedPgrp, " ");
    absl::StrAppend(&value, kExpectedSession, " ");
    absl::StrAppend(&value, kExpectedTtyNr, " ");
    absl::StrAppend(&value, kExpectedTpgid, " ");
    absl::StrAppend(&value, kExpectedFlags, " ");
    absl::StrAppend(&value, kExpectedMinFlt, " ");
    absl::StrAppend(&value, kExpectedCMinFlt, " ");
    absl::StrAppend(&value, kExpectedMajFlt, " ");
    absl::StrAppend(&value, kExpectedCMajFlt, " ");
    absl::StrAppend(&value, kExpectedUTime, " ");
    absl::StrAppend(&value, kExpectedSTime, " ");
    absl::StrAppend(&value, kExpectedCUTime, " ");
    absl::StrAppend(&value, kExpectedCSTime, " ");
    absl::StrAppend(&value, kExpectedPriority, " ");
    absl::StrAppend(&value, kExpectedNice, " ");
    absl::StrAppend(&value, kExpectedNumThreads, " ");
    absl::StrAppend(&value, kExpectedItRealValue, " ");
    absl::StrAppend(&value, kExpectedStartTime, " ");
    absl::StrAppend(&value, kExpectedVSize, " ");
    absl::StrAppend(&value, kExpectedRss, " ");
    absl::StrAppend(&value, kExpectedRssSLim, " ");
    absl::StrAppend(&value, kExpectedStartCode, " ");
    absl::StrAppend(&value, kExpectedEndCode, " ");
    absl::StrAppend(&value, kExpectedStartStack, " ");
    absl::StrAppend(&value, kExpectedKstKEsp, " ");
    absl::StrAppend(&value, kExpectedKstKEip, " ");
    absl::StrAppend(&value, kExpectedSignal, " ");
    absl::StrAppend(&value, kExpectedBlocked, " ");
    absl::StrAppend(&value, kExpectedSigIgnore, " ");
    absl::StrAppend(&value, kExpectedSigCatch, " ");
    absl::StrAppend(&value, kExpectedWChan, " ");
    absl::StrAppend(&value, kExpectedNSwap, " ");
    absl::StrAppend(&value, kExpectedCNSwap, " ");
    absl::StrAppend(&value, kExpectedExitSignal, " ");
    absl::StrAppend(&value, kExpectedProcessor, " ");
    absl::StrAppend(&value, kExpectedRtPriority, " ");
    absl::StrAppend(&value, kExpectedPolicy, " ");
    absl::StrAppend(&value, kExpectedDelayAcctBlkioTicks, " ");
    absl::StrAppend(&value, kExpectedGuestTime, " ");
    absl::StrAppend(&value, kExpectedCguestTime, " ");
    absl::StrAppend(&value, kExpectedStartData, " ");
    absl::StrAppend(&value, kExpectedEndData, " ");
    absl::StrAppend(&value, kExpectedStartBrk, " ");
    absl::StrAppend(&value, kExpectedArgStart, " ");
    absl::StrAppend(&value, kExpectedArgEnd, " ");
    absl::StrAppend(&value, kExpectedEnvStart, " ");
    absl::StrAppend(&value, kExpectedEnvEnd, " ");
    absl::StrAppend(&value, kExpectedExitCode);
    return value;
  }

  const std::string stat_contents_;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_MOCKS_MOCK_PROC_SYSTEM_PARSER_H_
