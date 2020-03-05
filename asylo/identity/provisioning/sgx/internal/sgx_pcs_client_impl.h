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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SGX_PCS_CLIENT_IMPL_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SGX_PCS_CLIENT_IMPL_H_

#include <memory>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "asylo/crypto/asymmetric_encryption_key.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.pb.h"
#include "asylo/util/http_fetcher.h"

namespace asylo {
namespace sgx {

// Implements SgxPcsClient using either a HttpFetcher to query SGX PCS APIs.
class SgxPcsClientImpl : public SgxPcsClient {
 public:
  ~SgxPcsClientImpl() override {}

  // |fetcher| is the underlying fetcher client. Must not be nullptr.
  // |ppid_enc_key| must be an RSA3072-OAEP encryption key used for encrypting
  // Platform Provisioning ID (PPID). Must not be nullptr. |api_key| is the
  // hex-encoded API key for access to Intel PCS GetPckCertificate(s) APIs.
  static StatusOr<std::unique_ptr<SgxPcsClient>> Create(
      std::unique_ptr<HttpFetcher> fetcher,
      std::unique_ptr<AsymmetricEncryptionKey> ppid_enc_key,
      absl::string_view api_key);

  // As above, but does not provide a PPID encryption key. All method calls on
  // the returned SgxPcsClient involving PPIDs will fail.
  static StatusOr<std::unique_ptr<SgxPcsClient>> CreateWithoutPpidEncryptionKey(
      std::unique_ptr<HttpFetcher> fetcher, absl::string_view api_key);

  // From SgxPcsClient.

  StatusOr<GetPckCertificateResult> GetPckCertificate(
      const Ppid &ppid, const CpuSvn &cpu_svn, const PceSvn &pce_svn,
      const PceId &pce_id) override;

  StatusOr<GetPckCertificatesResult> GetPckCertificates(
      const Ppid &ppid, const PceId &pce_id) override;

  StatusOr<GetCrlResult> GetCrl(SgxCaType sgx_ca_type) override;

  StatusOr<GetTcbInfoResult> GetTcbInfo(const Fmspc &fmspc) override;

 private:
  SgxPcsClientImpl(std::unique_ptr<HttpFetcher> fetcher,
                   std::unique_ptr<AsymmetricEncryptionKey> ppid_enc_key,
                   absl::string_view api_key);

  std::unique_ptr<HttpFetcher> fetcher_;
  std::unique_ptr<AsymmetricEncryptionKey> ppid_enc_key_;
  const std::string api_key_;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SGX_PCS_CLIENT_IMPL_H_
