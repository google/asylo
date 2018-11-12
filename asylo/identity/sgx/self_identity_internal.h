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

#ifndef ASYLO_IDENTITY_SGX_SELF_IDENTITY_INTERNAL_H_
#define ASYLO_IDENTITY_SGX_SELF_IDENTITY_INTERNAL_H_

// Note: This is an internal header; it must not be included in any files other
// than self_identity.cc and fake_self_identity.cc.

#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/sgx/self_identity.h"
#include "asylo/util/logging.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/identity/sgx/hardware_interface.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"

namespace asylo {
namespace sgx {

// The following constructor is defined in a header file so that it could be
// used across self_identity.cc and fake_self_identity.cc.
SelfIdentity::SelfIdentity() {
  AlignedTargetinfoPtr tinfo;
  AlignedReportdataPtr reportdata;
  AlignedReportPtr report;

  *tinfo = TrivialZeroObject<Targetinfo>();
  *reportdata = TrivialZeroObject<Reportdata>();

  if (!GetHardwareReport(*tinfo, *reportdata, report.get())) {
    LOG(FATAL) << "GetHardwareReport() failed";
  }

  cpusvn = report->cpusvn;
  miscselect = report->miscselect;
  attributes = report->attributes;
  mrenclave = report->mrenclave;
  mrsigner = report->mrsigner;
  isvprodid = report->isvprodid;
  isvsvn = report->isvsvn;

  Status status = ParseIdentityFromHardwareReport(*report, &identity);
  if (!status.ok()) {
    LOG(FATAL) << status;
  }
}

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_SELF_IDENTITY_INTERNAL_H_
