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

#include "asylo/platform/primitives/remote/metrics/proc_system_parser.h"

#include <unistd.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "asylo/platform/primitives/remote/metrics/mocks/mock_proc_system_parser.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::Return;

TEST(ProcSystemParserTest, ParsesProcStatFile) {
  const pid_t pid = fork();

  if (pid == 0) {
    // Busy process for testing.
    int sum = 0;
    const auto end_time = absl::Now() + absl::Seconds(2);
    while (absl::Now() < end_time) {
      for (int i = 0; i < 10000; i++) {
        sum += i;
      }
    }
    LOG(INFO) << "sum=" << sum;
    exit(0);
  }

  ASSERT_THAT(pid, Gt(0));

  ProcSystemStat proc_stat;
  auto proc_system_parser = absl::make_unique<ProcSystemParser>();
  ASYLO_ASSERT_OK_AND_ASSIGN(proc_stat, proc_system_parser->GetProcStat(pid));

  EXPECT_THAT(proc_stat.pid, Eq(pid));
  EXPECT_THAT(proc_stat.comm, Not(IsEmpty()));
  EXPECT_THAT(proc_stat.state, Not(IsEmpty()));
}

TEST(ProcSystemParserTest, CorrectlyParsesProcStatFile) {
  ProcSystemStat proc_stat;
  MockProcSystemParser mock_parser;

  EXPECT_CALL(mock_parser, ReadProcStat(_))
      .WillOnce(Return(mock_parser.stat_contents()));

  ASYLO_ASSERT_OK_AND_ASSIGN(proc_stat,
                             mock_parser.GetProcStat(mock_parser.kExpectedPid));

  EXPECT_THAT(proc_stat.pid, Eq(mock_parser.kExpectedPid));
  EXPECT_THAT(proc_stat.comm, Eq(mock_parser.kExpectedComm));
  EXPECT_THAT(proc_stat.state, Eq(mock_parser.kExpectedState));
  EXPECT_THAT(proc_stat.ppid, Eq(mock_parser.kExpectedPpid));
  EXPECT_THAT(proc_stat.pgrp, Eq(mock_parser.kExpectedPgrp));
  EXPECT_THAT(proc_stat.session, Eq(mock_parser.kExpectedSession));
  EXPECT_THAT(proc_stat.tty_nr, Eq(mock_parser.kExpectedTtyNr));
  EXPECT_THAT(proc_stat.tpgid, Eq(mock_parser.kExpectedTpgid));
  EXPECT_THAT(proc_stat.flags, Eq(mock_parser.kExpectedFlags));
  EXPECT_THAT(proc_stat.minflt, Eq(mock_parser.kExpectedMinFlt));
  EXPECT_THAT(proc_stat.cminflt, Eq(mock_parser.kExpectedCMinFlt));
  EXPECT_THAT(proc_stat.majflt, Eq(mock_parser.kExpectedMajFlt));
  EXPECT_THAT(proc_stat.cmajflt, Eq(mock_parser.kExpectedCMajFlt));
  EXPECT_THAT(proc_stat.utime, Eq(mock_parser.kExpectedUTime));
  EXPECT_THAT(proc_stat.stime, Eq(mock_parser.kExpectedSTime));
  EXPECT_THAT(proc_stat.cutime, Eq(mock_parser.kExpectedCUTime));
  EXPECT_THAT(proc_stat.cstime, Eq(mock_parser.kExpectedCSTime));
  EXPECT_THAT(proc_stat.priority, Eq(mock_parser.kExpectedPriority));
  EXPECT_THAT(proc_stat.nice, Eq(mock_parser.kExpectedNice));
  EXPECT_THAT(proc_stat.num_threads, Eq(mock_parser.kExpectedNumThreads));
  EXPECT_THAT(proc_stat.itrealvalue, Eq(mock_parser.kExpectedItRealValue));
  EXPECT_THAT(proc_stat.starttime, Eq(mock_parser.kExpectedStartTime));
  EXPECT_THAT(proc_stat.vsize, Eq(mock_parser.kExpectedVSize));
  EXPECT_THAT(proc_stat.rss, Eq(mock_parser.kExpectedRss));
  EXPECT_THAT(proc_stat.rsslim, Eq(mock_parser.kExpectedRssSLim));
  EXPECT_THAT(proc_stat.startcode, Eq(mock_parser.kExpectedStartCode));
  EXPECT_THAT(proc_stat.endcode, Eq(mock_parser.kExpectedEndCode));
  EXPECT_THAT(proc_stat.startstack, Eq(mock_parser.kExpectedStartStack));
  EXPECT_THAT(proc_stat.kstkesp, Eq(mock_parser.kExpectedKstKEsp));
  EXPECT_THAT(proc_stat.kstkeip, Eq(mock_parser.kExpectedKstKEip));
  EXPECT_THAT(proc_stat.signal, Eq(mock_parser.kExpectedSignal));
  EXPECT_THAT(proc_stat.blocked, Eq(mock_parser.kExpectedBlocked));
  EXPECT_THAT(proc_stat.sigignore, Eq(mock_parser.kExpectedSigIgnore));
  EXPECT_THAT(proc_stat.sigcatch, Eq(mock_parser.kExpectedSigCatch));
  EXPECT_THAT(proc_stat.wchan, Eq(mock_parser.kExpectedWChan));
  EXPECT_THAT(proc_stat.nswap, Eq(mock_parser.kExpectedNSwap));
  EXPECT_THAT(proc_stat.cnswap, Eq(mock_parser.kExpectedCNSwap));
  EXPECT_THAT(proc_stat.exit_signal, Eq(mock_parser.kExpectedExitSignal));
  EXPECT_THAT(proc_stat.processor, Eq(mock_parser.kExpectedProcessor));
  EXPECT_THAT(proc_stat.rt_priority, Eq(mock_parser.kExpectedRtPriority));
  EXPECT_THAT(proc_stat.policy, Eq(mock_parser.kExpectedPolicy));
  EXPECT_THAT(proc_stat.delayacct_blkio_ticks,
              Eq(mock_parser.kExpectedDelayAcctBlkioTicks));
  EXPECT_THAT(proc_stat.guest_time, Eq(mock_parser.kExpectedGuestTime));
  EXPECT_THAT(proc_stat.cguest_time, Eq(mock_parser.kExpectedCguestTime));
  EXPECT_THAT(proc_stat.start_data, Eq(mock_parser.kExpectedStartData));
  EXPECT_THAT(proc_stat.end_data, Eq(mock_parser.kExpectedEndData));
  EXPECT_THAT(proc_stat.start_brk, Eq(mock_parser.kExpectedStartBrk));
  EXPECT_THAT(proc_stat.arg_start, Eq(mock_parser.kExpectedArgStart));
  EXPECT_THAT(proc_stat.arg_end, Eq(mock_parser.kExpectedArgEnd));
  EXPECT_THAT(proc_stat.env_start, Eq(mock_parser.kExpectedEnvStart));
  EXPECT_THAT(proc_stat.env_end, Eq(mock_parser.kExpectedEnvEnd));
  EXPECT_THAT(proc_stat.exit_code, Eq(mock_parser.kExpectedExitCode));
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
