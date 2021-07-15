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

#include "asylo/platform/primitives/remote/metrics/proc_system_service.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "asylo/platform/primitives/remote/metrics/mocks/mock_proc_system_parser.h"
#include "asylo/platform/primitives/remote/metrics/mocks/mock_proc_system_service.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_helpers.h"

namespace asylo {
namespace primitives {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::Gt;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::Return;

class ProcSystemServiceTest : public ::testing::Test {
 protected:
  ::grpc::ServerContext context_;
  ProcStatRequest proc_stat_request_;
  ProcStatResponse proc_stat_response_;
};

TEST_F(ProcSystemServiceTest, SuccessfullyBuildsResponse) {
  const pid_t pid = fork();

  if (pid == 0) {
    // Busy process for testing.
    const auto end_time = absl::Now() + absl::Seconds(2);
    while (absl::Now() < end_time) {
      int sum = 0;
      for (int i = 0; i < 10000; i++) {
        sum += i;
      }
      (void)sum;
    }
    exit(0);
  }

  ASSERT_THAT(pid, Gt(0));
  ProcSystemServiceImpl proc_system_service_(pid);
  ASYLO_ASSERT_OK(ConvertStatus<asylo::Status>(proc_system_service_.GetProcStat(
      &context_, &proc_stat_request_, &proc_stat_response_)));

  auto proc_stat = proc_stat_response_.proc_stat();
  EXPECT_THAT(proc_stat.pid(), Eq(pid));
  EXPECT_THAT(proc_stat.comm(), Not(IsEmpty()));
  EXPECT_THAT(proc_stat.state(), Not(IsEmpty()));
}

TEST_F(ProcSystemServiceTest, ResponseIsSuccessfulParse) {
  auto mock_parser = absl::make_unique<MockProcSystemParser>();
  EXPECT_CALL(*mock_parser, ReadProcStat(_))
      .WillOnce(Return(mock_parser->stat_contents()));

  // |mock_parser| is consumed by |mock_service|. Need a second instance for
  // comparison.
  const auto comparison_parser = mock_parser.get();

  MockProcSystemService mock_service(std::move(mock_parser),
                                     comparison_parser->kExpectedPid);

  ASYLO_ASSERT_OK(ConvertStatus<asylo::Status>(mock_service.GetProcStat(
      &context_, &proc_stat_request_, &proc_stat_response_)));
  auto response_proc_stat = proc_stat_response_.proc_stat();

  EXPECT_THAT(response_proc_stat.pid(), Eq(comparison_parser->kExpectedPid));
  EXPECT_THAT(response_proc_stat.comm(), Eq(comparison_parser->kExpectedComm));
  EXPECT_THAT(response_proc_stat.state(),
              Eq(comparison_parser->kExpectedState));
  EXPECT_THAT(response_proc_stat.ppid(), Eq(comparison_parser->kExpectedPpid));
  EXPECT_THAT(response_proc_stat.pgrp(), Eq(comparison_parser->kExpectedPgrp));
  EXPECT_THAT(response_proc_stat.session(),
              Eq(comparison_parser->kExpectedSession));
  EXPECT_THAT(response_proc_stat.tty_nr(),
              Eq(comparison_parser->kExpectedTtyNr));
  EXPECT_THAT(response_proc_stat.tpgid(),
              Eq(comparison_parser->kExpectedTpgid));
  EXPECT_THAT(response_proc_stat.flags(),
              Eq(comparison_parser->kExpectedFlags));
  EXPECT_THAT(response_proc_stat.minflt(),
              Eq(comparison_parser->kExpectedMinFlt));
  EXPECT_THAT(response_proc_stat.cminflt(),
              Eq(comparison_parser->kExpectedCMinFlt));
  EXPECT_THAT(response_proc_stat.majflt(),
              Eq(comparison_parser->kExpectedMajFlt));
  EXPECT_THAT(response_proc_stat.cmajflt(),
              Eq(comparison_parser->kExpectedCMajFlt));
  EXPECT_THAT(response_proc_stat.utime(),
              Eq(comparison_parser->kExpectedUTime));
  EXPECT_THAT(response_proc_stat.stime(),
              Eq(comparison_parser->kExpectedSTime));
  EXPECT_THAT(response_proc_stat.cutime(),
              Eq(comparison_parser->kExpectedCUTime));
  EXPECT_THAT(response_proc_stat.cstime(),
              Eq(comparison_parser->kExpectedCSTime));
  EXPECT_THAT(response_proc_stat.priority(),
              Eq(comparison_parser->kExpectedPriority));
  EXPECT_THAT(response_proc_stat.nice(), Eq(comparison_parser->kExpectedNice));
  EXPECT_THAT(response_proc_stat.num_threads(),
              Eq(comparison_parser->kExpectedNumThreads));
  EXPECT_THAT(response_proc_stat.itrealvalue(),
              Eq(comparison_parser->kExpectedItRealValue));
  EXPECT_THAT(response_proc_stat.starttime(),
              Eq(comparison_parser->kExpectedStartTime));
  EXPECT_THAT(response_proc_stat.vsize(),
              Eq(comparison_parser->kExpectedVSize));
  EXPECT_THAT(response_proc_stat.rss(), Eq(comparison_parser->kExpectedRss));
  EXPECT_THAT(response_proc_stat.rsslim(),
              Eq(comparison_parser->kExpectedRssSLim));
  EXPECT_THAT(response_proc_stat.startcode(),
              Eq(comparison_parser->kExpectedStartCode));
  EXPECT_THAT(response_proc_stat.endcode(),
              Eq(comparison_parser->kExpectedEndCode));
  EXPECT_THAT(response_proc_stat.startstack(),
              Eq(comparison_parser->kExpectedStartStack));
  EXPECT_THAT(response_proc_stat.kstkesp(),
              Eq(comparison_parser->kExpectedKstKEsp));
  EXPECT_THAT(response_proc_stat.kstkeip(),
              Eq(comparison_parser->kExpectedKstKEip));
  EXPECT_THAT(response_proc_stat.signal(),
              Eq(comparison_parser->kExpectedSignal));
  EXPECT_THAT(response_proc_stat.blocked(),
              Eq(comparison_parser->kExpectedBlocked));
  EXPECT_THAT(response_proc_stat.sigignore(),
              Eq(comparison_parser->kExpectedSigIgnore));
  EXPECT_THAT(response_proc_stat.sigcatch(),
              Eq(comparison_parser->kExpectedSigCatch));
  EXPECT_THAT(response_proc_stat.wchan(),
              Eq(comparison_parser->kExpectedWChan));
  EXPECT_THAT(response_proc_stat.nswap(),
              Eq(comparison_parser->kExpectedNSwap));
  EXPECT_THAT(response_proc_stat.cnswap(),
              Eq(comparison_parser->kExpectedCNSwap));
  EXPECT_THAT(response_proc_stat.exit_signal(),
              Eq(comparison_parser->kExpectedExitSignal));
  EXPECT_THAT(response_proc_stat.processor(),
              Eq(comparison_parser->kExpectedProcessor));
  EXPECT_THAT(response_proc_stat.rt_priority(),
              Eq(comparison_parser->kExpectedRtPriority));
  EXPECT_THAT(response_proc_stat.policy(),
              Eq(comparison_parser->kExpectedPolicy));
  EXPECT_THAT(response_proc_stat.delayacct_blkio_ticks(),
              Eq(comparison_parser->kExpectedDelayAcctBlkioTicks));
  EXPECT_THAT(response_proc_stat.guest_time(),
              Eq(comparison_parser->kExpectedGuestTime));
  EXPECT_THAT(response_proc_stat.cguest_time(),
              Eq(comparison_parser->kExpectedCguestTime));
  EXPECT_THAT(response_proc_stat.start_data(),
              Eq(comparison_parser->kExpectedStartData));
  EXPECT_THAT(response_proc_stat.end_data(),
              Eq(comparison_parser->kExpectedEndData));
  EXPECT_THAT(response_proc_stat.start_brk(),
              Eq(comparison_parser->kExpectedStartBrk));
  EXPECT_THAT(response_proc_stat.arg_start(),
              Eq(comparison_parser->kExpectedArgStart));
  EXPECT_THAT(response_proc_stat.arg_end(),
              Eq(comparison_parser->kExpectedArgEnd));
  EXPECT_THAT(response_proc_stat.env_start(),
              Eq(comparison_parser->kExpectedEnvStart));
  EXPECT_THAT(response_proc_stat.env_end(),
              Eq(comparison_parser->kExpectedEnvEnd));
  EXPECT_THAT(response_proc_stat.exit_code(),
              Eq(comparison_parser->kExpectedExitCode));
}

}  // namespace
}  // namespace primitives
}  // namespace asylo
