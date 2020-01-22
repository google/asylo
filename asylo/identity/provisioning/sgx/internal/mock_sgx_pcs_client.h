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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_MOCK_SGX_PCS_CLIENT_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_MOCK_SGX_PCS_CLIENT_H_

#include <gmock/gmock.h>
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

class MockSgxPcsClient : public SgxPcsClient {
 public:
  MOCK_METHOD(StatusOr<GetPckCertificateResult>, GetPckCertificate,
              (const Ppid &, const CpuSvn &, const PceSvn &, const PceId &),
              (override));

  MOCK_METHOD(StatusOr<GetPckCertificatesResult>, GetPckCertificates,
              (const Ppid &, const PceId &), (override));

  MOCK_METHOD(StatusOr<GetCrlResult>, GetCrl, (SgxCaType), (override));

  MOCK_METHOD(StatusOr<GetTcbInfoResult>, GetTcbInfo, (const Fmspc &),
              (override));
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_MOCK_SGX_PCS_CLIENT_H_
