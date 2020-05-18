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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_MOCK_HARDWARE_INTERFACE_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_MOCK_HARDWARE_INTERFACE_H_

#include <cstdint>

#include <gmock/gmock.h>
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// Mock for testing code that depends on `HardwareInterface`.
class MockHardwareInterface : public HardwareInterface {
 public:
  MOCK_METHOD(StatusOr<uint64_t>, GetRand64, (), (const override));
  MOCK_METHOD(StatusOr<HardwareKey>, GetKey, (const Keyrequest &),
              (const override));
  MOCK_METHOD(StatusOr<Report>, GetReport,
              (const Targetinfo &, const Reportdata &), (const override));
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_MOCK_HARDWARE_INTERFACE_H_
