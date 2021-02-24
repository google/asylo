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

#include <linux/sched.h>
#include <sys/types.h>

#include <fstream>
#include <iostream>
#include <sstream>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "asylo/util/asylo_macros.h"
#include "asylo/util/cleanup.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

// TASK_COMM_LEN should be defined in linux/sched.h. In the event it isn't, we
// set it to the standard value squared. (The standard is 16, so 16^2)
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 256
#endif

namespace asylo {
namespace primitives {
namespace {

StatusOr<std::string> GetFileContents(const std::string &filename) {
  std::ifstream file;
  Cleanup file_cleanup([&file]() { file.close(); });
  file.open(filename.c_str());
  if (!file) {
    return absl::UnknownError(
        absl::StrCat("Unable to open file with filename=", filename));
  }

  std::stringstream file_contents;
  file_contents << file.rdbuf();
  return file_contents.str();
}

}  // namespace

StatusOr<std::string> ProcSystemParser::ReadProcStat(pid_t pid) const {
  std::string stat_contents;
  ASYLO_ASSIGN_OR_RETURN(stat_contents,
                         GetFileContents(absl::StrCat("/proc/", pid, "/stat")));
  return stat_contents;
}

StatusOr<ProcSystemStat> ProcSystemParser::GetProcStat(pid_t pid) const {
  std::string stat_contents;
  ASYLO_ASSIGN_OR_RETURN(stat_contents, ReadProcStat(pid));
  // Maximum character length of a stat file plus a null character.
  static constexpr uint64_t kStatFileLength = TASK_COMM_LEN + 1002;
  char stat_contents_c_str[kStatFileLength];
  absl::SNPrintF(stat_contents_c_str, sizeof(stat_contents_c_str), "%s",
                 stat_contents);

  ProcSystemStat proc_stat;

  // Get the PID and ensure we got the right file.
  sscanf(stat_contents_c_str, "%ld ...", &proc_stat.pid);
  if (proc_stat.pid != pid) {
    return absl::UnknownError(
        absl::StrCat("Got wrong pid while parsing /proc/", pid, "/stat"));
  }

  // The format for the /proc/[pid]/stat file requires that process' filename be
  // surrounded by parenthenses, but does not prevent the process' filename from
  // having parenthenses in itself. Linux header |include/linux/sched.h| limits
  // the process' filename TASK_COMM_LEN. So here we set the filename length to
  // TASK_COMM_LENGTH for the filename plus two for the parenthenses;
  static constexpr uint64_t kFilenameLength = TASK_COMM_LEN + 2;

  // We add one byte for the terminating character.
  char process_filename[kFilenameLength + 1];

  char *start = nullptr;
  char *end = nullptr;

  // This loop scans through the stat contents and finds the beginning and end
  // of the process' filename. |start| is set to the first open parenthenses,
  // and |end| is set to the last parenthenses. This has the unfortunate side
  // effect of needing to scan the entire string.
  for (char *peek = stat_contents_c_str; *peek != '\0'; peek++) {
    if (start == nullptr && *peek == '(') {
      start = peek;
    }
    if (start != nullptr && peek - start <= kFilenameLength) {
      process_filename[peek - start] = *peek;
    }

    // May set multiple times, retaining the last ')' found.
    if (*peek == ')') {
      end = peek;
    }
  }

  // If we are unable to find end of filename, or filename was too long the
  // format of the file is unexpected.
  if (end == nullptr || end - start > kFilenameLength) {
    return absl::InternalError(absl::StrCat("/proc/", pid,
                                            "/stat file was not formatted as "
                                            "expected. Unable to parse."));
  }

  // Set the character after the final ')' to a null.
  process_filename[end - start + 1] = '\0';

  // Iterate |end| pointer past the space at the end of the process filename.
  // This lines |end| up with the |state| field.
  end += 2;

  // |end| is now lined up with state field and there are no more special
  // fields that need processing, sscanf can parse the remaining items.
  static constexpr char kFormatString[] =         // Index of last item.
      "%c %ld %ld %ld %ld %ld %lu %lu %lu %lu "   // 12
      "%lu %lu %lu %ld %ld %ld %ld %ld %ld %lu "  // 22
      "%lu %ld %lu %lu %lu %lu %lu %lu %lu %lu "  // 32
      "%lu %lu %lu %lu %lu %ld %ld %lu %lu %lu "  // 42
      "%lu %ld %lu %lu %lu %lu %lu %lu %lu %ld";  // 52

  char state;
  int check = sscanf(
      end, kFormatString, &state, &proc_stat.ppid, &proc_stat.pgrp,
      &proc_stat.session, &proc_stat.tty_nr, &proc_stat.tpgid, &proc_stat.flags,
      &proc_stat.minflt, &proc_stat.cminflt, &proc_stat.majflt,
      &proc_stat.cmajflt, &proc_stat.utime, &proc_stat.stime, &proc_stat.cutime,
      &proc_stat.cstime, &proc_stat.priority, &proc_stat.nice,
      &proc_stat.num_threads, &proc_stat.itrealvalue, &proc_stat.starttime,
      &proc_stat.vsize, &proc_stat.rss, &proc_stat.rsslim, &proc_stat.startcode,
      &proc_stat.endcode, &proc_stat.startstack, &proc_stat.kstkesp,
      &proc_stat.kstkeip, &proc_stat.signal, &proc_stat.blocked,
      &proc_stat.sigignore, &proc_stat.sigcatch, &proc_stat.wchan,
      &proc_stat.nswap, &proc_stat.cnswap, &proc_stat.exit_signal,
      &proc_stat.processor, &proc_stat.rt_priority, &proc_stat.policy,
      &proc_stat.delayacct_blkio_ticks, &proc_stat.guest_time,
      &proc_stat.cguest_time, &proc_stat.start_data, &proc_stat.end_data,
      &proc_stat.start_brk, &proc_stat.arg_start, &proc_stat.arg_end,
      &proc_stat.env_start, &proc_stat.env_end, &proc_stat.exit_code);

  // The expectation is that 50 values were set by sscanf. If that is not the
  // case, the file was not formatted as expected.
  if (check != 50) {
    return absl::InternalError(absl::StrCat("/proc/", pid,
                                            "/stat file was not formatted as "
                                            "expected. Unable to parse."));
  }

  proc_stat.comm = process_filename;
  proc_stat.state = std::string(&state, 1);

  return proc_stat;
}

}  // namespace primitives
}  // namespace asylo
