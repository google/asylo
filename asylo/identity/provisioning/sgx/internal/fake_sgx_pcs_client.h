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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_FAKE_SGX_PCS_CLIENT_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_FAKE_SGX_PCS_CLIENT_H_

#include <memory>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/hash/hash.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/identity/provisioning/sgx/internal/container_util.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/identity/sgx/machine_configuration.pb.h"
#include "asylo/util/mutex_guarded.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

// A fake implementation of SgxPcsClient. FakeSgxPcsClient is thread-safe. Each
// FakeSgxPcsClient stores a map from a set of known FMSPCs to TCB infos.
//
// FakeSgxPcsClient relies on an internal fake FMSPC layout to determine the
// properties of the fake platform type corresponding to a given fake FMSPC.
// This layout is hard-coded, so two FakeSgxPcsClients running in different
// processes will both identify a given FMSPC as representing a platform with
// the same properties.
class FakeSgxPcsClient : public SgxPcsClient {
 public:
  // A fake SGX platform type. The information in this struct is embedded in
  // each fake FMSPC created for this type.
  struct PlatformProperties {
    // The CA that issues this platform's PCK certificates.
    SgxCaType ca;

    // The PCE ID used by the platform.
    PceId pce_id;
  };

  // Constructs a new FakeSgxPcsClient using the fake PKI in fake_sgx_pki.h.
  FakeSgxPcsClient();

  // Adds |fmspc| to the set of known FMSPCs and associates it with |tcb_info|,
  // which must have a |version| of 2.
  //
  // If the |fmspc| is already in the set of known FMSPCs, then AddFmspc()
  // returns false and does not modify existing data. Otherwise, AddFmspc()
  // returns true.
  //
  // AddFmspc() returns an error if |fmspc| does not match the internal FMSPC
  // format. To create a matching FMSPC, use CreateFmspcWithProperties().
  StatusOr<bool> AddFmspc(Fmspc fmspc, TcbInfo tcb_info);

  // Changes the TCB info associated with |fmspc| to be |tcb_info|, which must
  // have a |version| of 2.
  //
  // Returns an error if |fmspc| is not valid or is not in the set of known
  // FMSPCs.
  Status UpdateFmspc(const Fmspc &fmspc, TcbInfo tcb_info);

  // From SgxPcsClient. Currently unimplemented.
  StatusOr<GetPckCertificateResult> GetPckCertificate(
      const Ppid &ppid, const CpuSvn &cpu_svn, const PceSvn &pce_svn,
      const PceId &pce_id) override;

  // From SgxPcsClient. Currently unimplemented.
  StatusOr<GetPckCertificatesResult> GetPckCertificates(
      const Ppid &ppid, const PceId &pce_id) override;

  // From SgxPcsClient. Currently unimplemented.
  StatusOr<GetCrlResult> GetCrl(SgxCaType sgx_ca_type) override;

  // From SgxPcsClient. Returns the TCB info associated with |fmspc|, but
  // modified to have an "issueDate" corresponding to the current time and a
  // "nextUpdate" one month later.
  //
  // The returned signatures over the TCB info may differ between calls, but
  // they will all be correct signatures.
  //
  // GetTcbInfo() returns an error if:
  //
  //   * |fmspc| is invalid.
  //   * |fmspc| is not in the set of known FMSPCs.
  //
  StatusOr<GetTcbInfoResult> GetTcbInfo(const Fmspc &fmspc) override;

  // Returns a new random FMSPC that a FakeSgxPcsClient will associate with
  // |type|. Callers should be careful to check for collisions with previous
  // randomly-generated FMSPCs.
  static StatusOr<Fmspc> CreateFmspcWithProperties(
      const PlatformProperties &properties);

 private:
  using FmspcToTcbInfoMap =
      absl::flat_hash_map<Fmspc, TcbInfo, absl::Hash<Fmspc>, MessageEqual>;

  const CertificateChain tcb_info_issuer_chain_;
  const std::unique_ptr<const SigningKey> tcb_info_signing_key_;
  MutexGuarded<FmspcToTcbInfoMap> tcb_infos_;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_FAKE_SGX_PCS_CLIENT_H_