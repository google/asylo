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

#include "absl/memory/memory.h"
#include "asylo/identity/platform/sgx/internal/fake_enclave.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"

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

class FakeHardwareInterface : public HardwareInterface {
 public:
  StatusOr<HardwareKey> GetKey(const Keyrequest &request) const override {
    FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

    if (enclave == nullptr) {
      enclave = SetNewRandomEnclave();
    }

    AlignedHardwareKeyPtr key;
    ASYLO_RETURN_IF_ERROR(enclave->GetHardwareKey(request, key.get()));
    return *key;
  }

  StatusOr<Report> GetReport(const Targetinfo &tinfo,
                             const Reportdata &reportdata) const override {
    FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

    if (enclave == nullptr) {
      enclave = SetNewRandomEnclave();
    }

    AlignedReportPtr report;
    ASYLO_RETURN_IF_ERROR(
        enclave->GetHardwareReport(tinfo, reportdata, report.get()));
    return *report;
  }
};

}  // namespace

std::unique_ptr<HardwareInterface> HardwareInterface::CreateDefault() {
  return absl::make_unique<FakeHardwareInterface>();
}

}  // namespace sgx
}  // namespace asylo
