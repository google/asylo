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

#ifndef ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_PROC_SYSTEM_PARSER_H_
#define ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_PROC_SYSTEM_PARSER_H_

#include <sys/types.h>

#include "asylo/util/statusor.h"

namespace asylo {
namespace primitives {

struct ProcSystemStat {
 public:
  int64_t cguest_time, cstime, cutime, exit_code, exit_signal, itrealvalue,
      nice, num_threads, pgrp, pid, ppid, priority, processor, rss, session,
      tpgid, tty_nr;
  std::string comm, state;
  uint64_t arg_end, arg_start, blocked, cmajflt, cminflt, cnswap,
      delayacct_blkio_ticks, end_data, endcode, env_end, env_start, flags,
      guest_time, kstkeip, kstkesp, majflt, minflt, nswap, policy, rsslim,
      rt_priority, sigcatch, sigignore, signal, start_brk, start_data,
      startcode, startstack, starttime, stime, utime, vsize, wchan;
};

// |ProcSystemParser| parses proc system files into their respective structs.
class ProcSystemParser {
 public:
  ProcSystemParser() = default;
  ProcSystemParser(const ProcSystemParser &other) = delete;
  ProcSystemParser &operator=(const ProcSystemParser &other) = delete;

  virtual ~ProcSystemParser() = default;

  // Will parse the /proc/[pid]/stat file of a given process id into a
  // |ProcSystemStat|.
  StatusOr<ProcSystemStat> GetProcStat(pid_t pid) const;

 private:
  virtual StatusOr<std::string> ReadProcStat(pid_t pid) const;
};

}  // namespace primitives
}  // namespace asylo

#endif  // ASYLO_PLATFORM_PRIMITIVES_REMOTE_METRICS_PROC_SYSTEM_PARSER_H_
