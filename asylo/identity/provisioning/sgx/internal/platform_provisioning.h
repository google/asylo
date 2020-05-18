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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_PLATFORM_PROVISIONING_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_PLATFORM_PROVISIONING_H_

#include <cstdint>

#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// The maximum value of a PceSvn's |value| field.
extern const uint32_t kPceSvnMaxValue;

// The maximum value of a PceId's |value| field.
extern const uint32_t kPceIdMaxValue;

// Validates a ConfigurationId message. Return an OK status if and only if the
// message is valid.
Status ValidateConfigurationId(const ConfigurationId &id);

// Validates a Ppid message. Returns an OK status if and only if the message is
// valid.
Status ValidatePpid(const Ppid &ppid);

// Validates a CpuSvn message. Returns an OK status if and only if the message
// is valid.
Status ValidateCpuSvn(const CpuSvn &cpu_svn);

// Validates a PceSvn message. Returns an OK status if and only if the message
// is valid.
Status ValidatePceSvn(const PceSvn &pce_svn);

// Validates a PceId message. Returns an OK status if and only if the message
// is valid.
Status ValidatePceId(const PceId &pce_id);

// Validates an Fmspc message. Returns an OK status if and only if the message
// is valid.
Status ValidateFmspc(const Fmspc &fmspc);

// Validates a ReportProto message. Returns an OK status if and only if the
// message is valid.
Status ValidateReportProto(const ReportProto &report_proto);

// Validates a TargetInfoProto message. Returns an OK status if and only if the
// message is valid.
Status ValidateTargetInfoProto(const TargetInfoProto &target_info_proto);

// Extracts the contents of |report_proto| to a REPORT structure. Returns an
// error if the message is invalid.
StatusOr<Report> ConvertReportProtoToHardwareReport(
    const ReportProto &report_proto);

// Extracts the contents of |target_info_proto| to a TARGETINFO structure.
// Returns an error if the message is invalid.
StatusOr<Targetinfo> ConvertTargetInfoProtoToTargetinfo(
    const TargetInfoProto &target_info_proto);

// Extracts a CpuSvn from the given |report_proto|. Returns an error if the
// message is invalid.
StatusOr<CpuSvn> CpuSvnFromReportProto(const ReportProto &report_proto);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_PLATFORM_PROVISIONING_H_
