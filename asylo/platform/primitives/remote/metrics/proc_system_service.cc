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

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/platform/primitives/remote/metrics/proc_system.grpc.pb.h"
#include "asylo/platform/primitives/remote/metrics/proc_system.pb.h"
#include "asylo/platform/primitives/remote/metrics/proc_system_parser.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/support/status.h"

namespace asylo {
namespace primitives {

::grpc::Status ProcSystemServiceImpl::GetProcStat(
    grpc::ServerContext *context, const ProcStatRequest *request,
    ProcStatResponse *response) {
  auto status = BuildProcStatResponse(response);
  if (!status.ok()) {
    LOG(ERROR) << status;
    return ConvertStatus<::grpc::Status>(status);
  }
  return ::grpc::Status::OK;
}

std::unique_ptr<ProcSystemParser>
ProcSystemServiceImpl::CreateProcSystemParser() const {
  return absl::make_unique<ProcSystemParser>();
}

::asylo::Status ProcSystemServiceImpl::BuildProcStatResponse(
    ProcStatResponse *response) const {
  ProcSystemStat proc_stat;
  ASYLO_ASSIGN_OR_RETURN(proc_stat, proc_system_parser_->GetProcStat(pid_));
  auto response_proc_stat = response->mutable_proc_stat();
  response_proc_stat->set_pid(proc_stat.pid);
  response_proc_stat->set_comm(proc_stat.comm);
  response_proc_stat->set_state(proc_stat.state);
  response_proc_stat->set_ppid(proc_stat.ppid);
  response_proc_stat->set_pgrp(proc_stat.pgrp);
  response_proc_stat->set_session(proc_stat.session);
  response_proc_stat->set_tty_nr(proc_stat.tty_nr);
  response_proc_stat->set_tpgid(proc_stat.tpgid);
  response_proc_stat->set_flags(proc_stat.flags);
  response_proc_stat->set_minflt(proc_stat.minflt);
  response_proc_stat->set_cminflt(proc_stat.cminflt);
  response_proc_stat->set_majflt(proc_stat.majflt);
  response_proc_stat->set_cmajflt(proc_stat.cmajflt);
  response_proc_stat->set_utime(proc_stat.utime);
  response_proc_stat->set_stime(proc_stat.stime);
  response_proc_stat->set_cutime(proc_stat.cutime);
  response_proc_stat->set_cstime(proc_stat.cstime);
  response_proc_stat->set_priority(proc_stat.priority);
  response_proc_stat->set_nice(proc_stat.nice);
  response_proc_stat->set_num_threads(proc_stat.num_threads);
  response_proc_stat->set_itrealvalue(proc_stat.itrealvalue);
  response_proc_stat->set_starttime(proc_stat.starttime);
  response_proc_stat->set_vsize(proc_stat.vsize);
  response_proc_stat->set_rss(proc_stat.rss);
  response_proc_stat->set_rsslim(proc_stat.rsslim);
  response_proc_stat->set_startcode(proc_stat.startcode);
  response_proc_stat->set_endcode(proc_stat.endcode);
  response_proc_stat->set_startstack(proc_stat.startstack);
  response_proc_stat->set_kstkesp(proc_stat.kstkesp);
  response_proc_stat->set_kstkeip(proc_stat.kstkeip);
  response_proc_stat->set_signal(proc_stat.signal);
  response_proc_stat->set_blocked(proc_stat.blocked);
  response_proc_stat->set_sigignore(proc_stat.sigignore);
  response_proc_stat->set_sigcatch(proc_stat.sigcatch);
  response_proc_stat->set_wchan(proc_stat.wchan);
  response_proc_stat->set_nswap(proc_stat.nswap);
  response_proc_stat->set_cnswap(proc_stat.cnswap);
  response_proc_stat->set_exit_signal(proc_stat.exit_signal);
  response_proc_stat->set_processor(proc_stat.processor);
  response_proc_stat->set_rt_priority(proc_stat.rt_priority);
  response_proc_stat->set_policy(proc_stat.policy);
  response_proc_stat->set_delayacct_blkio_ticks(
      proc_stat.delayacct_blkio_ticks);
  response_proc_stat->set_guest_time(proc_stat.guest_time);
  response_proc_stat->set_cguest_time(proc_stat.cguest_time);
  response_proc_stat->set_start_data(proc_stat.start_data);
  response_proc_stat->set_end_data(proc_stat.end_data);
  response_proc_stat->set_start_brk(proc_stat.start_brk);
  response_proc_stat->set_arg_start(proc_stat.arg_start);
  response_proc_stat->set_arg_end(proc_stat.arg_end);
  response_proc_stat->set_env_start(proc_stat.env_start);
  response_proc_stat->set_env_end(proc_stat.env_end);
  response_proc_stat->set_exit_code(proc_stat.exit_code);
  return ::absl::OkStatus();
}

}  // namespace primitives
}  // namespace asylo
