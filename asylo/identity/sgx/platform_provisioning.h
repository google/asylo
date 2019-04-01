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

#ifndef ASYLO_IDENTITY_SGX_PLATFORM_PROVISIONING_H_
#define ASYLO_IDENTITY_SGX_PLATFORM_PROVISIONING_H_

#include "asylo/identity/sgx/platform_provisioning.pb.h"
#include "asylo/util/status.h"

namespace asylo {
namespace sgx {

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

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_PLATFORM_PROVISIONING_H_
