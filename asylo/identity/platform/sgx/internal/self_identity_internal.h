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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SELF_IDENTITY_INTERNAL_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SELF_IDENTITY_INTERNAL_H_

// Note: This is an internal header; it must not be included in any files other
// than self_identity.cc and fake_self_identity.cc.

#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/util/logging.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/self_identity.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"

namespace asylo {
namespace sgx {

// The following constructor is defined in a header file so that it could be
// used across self_identity.cc and fake_self_identity.cc.
SelfIdentity::SelfIdentity() {
  AlignedTargetinfoPtr tinfo;
  AlignedReportdataPtr reportdata;

  *tinfo = TrivialZeroObject<Targetinfo>();
  *reportdata = TrivialZeroObject<Reportdata>();

  Report report = HardwareInterface::CreateDefault()
                      ->GetReport(*tinfo, *reportdata)
                      .value();

  cpusvn = report.body.cpusvn;
  miscselect = report.body.miscselect;
  attributes = report.body.attributes;
  mrenclave = report.body.mrenclave;
  mrsigner = report.body.mrsigner;
  isvprodid = report.body.isvprodid;
  isvsvn = report.body.isvsvn;

  sgx_identity = ParseSgxIdentityFromHardwareReport(report.body);
}

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_SELF_IDENTITY_INTERNAL_H_
