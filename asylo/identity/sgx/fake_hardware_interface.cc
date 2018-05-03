/*
 *
 * Copyright 2017 Asylo authors
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

// fake_hardware_interface.cc is one implementation of the interface defined
// in hardware_interface.h, and consequently it is included as the related
// header and not a general, unrelated header.
#include "asylo/identity/sgx/hardware_interface.h"

#include "asylo/identity/sgx/fake_enclave.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"

#ifdef __ASYLO__
#error "Must not use the fake hardware interface inside an enclave"
#endif

namespace asylo {
namespace sgx {
namespace {

FakeEnclave *SetNewRandomEnclave() {
  FakeEnclave new_enclave;
  new_enclave.SetRandomIdentity();
  FakeEnclave::EnterEnclave(new_enclave);
  return FakeEnclave::GetCurrentEnclave();
}

}  // namespace

bool GetHardwareRand64(uint64_t *value) {
  return FakeEnclave::GetHardwareRand64(value);
}

bool GetHardwareKey(const Keyrequest &request, HardwareKey *key) {
  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  if (enclave == nullptr) {
    enclave = SetNewRandomEnclave();
  }
  return enclave->GetHardwareKey(request, key);
}

bool GetHardwareReport(const Targetinfo &tinfo, const Reportdata &reportdata,
                       Report *report) {
  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  if (enclave == nullptr) {
    enclave = SetNewRandomEnclave();
  }

  return enclave->GetHardwareReport(tinfo, reportdata, report);
}

}  // namespace sgx
}  // namespace asylo
