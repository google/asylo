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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SGX_PCS_CLIENT_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SGX_PCS_CLIENT_H_

#include "asylo/crypto/certificate.pb.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/pck_certificates.pb.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/sgx_pcs_client.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {

struct GetPckCertificateResult {
  // PCK certificate.
  Certificate pck_cert;
  // Issuer certificate chain.
  CertificateChain issuer_cert_chain;
  // TCB identifier.
  RawTcb tcbm;
};

struct GetPckCertificatesResult {
  // Contains a sequence of PCK certificates and TCB infos.
  PckCertificates pck_certs;
  // Issuer certificate chain.
  CertificateChain issuer_cert_chain;
};

struct GetCrlResult {
  // Certificate revocation list.
  CertificateRevocationList pck_crl;
  // Issuer certificate chain.
  CertificateChain issuer_cert_chain;
};

struct GetTcbInfoResult {
  // TCB info with signature.
  SignedTcbInfo tcb_info;
  // Issuer certificate chain.
  CertificateChain issuer_cert_chain;
};

// Client used to retrieve information from Intel SGX Provisioning Certification
// Service (PCS). See https://api.portal.trustedservices.intel.com/documentation
// for details.
//
// All classes implementing the interface should be thread safe.
class SgxPcsClient {
 public:
  virtual ~SgxPcsClient() {}

  // Retrieves X.509 SGX Provisioning Certification Key (PCK) certificate for
  // the SGX-enabled platform identitifed by |ppid| and |pce_id|, and for the
  // TCB level specified by |cpu_svn| and |pce_svn|.
  virtual StatusOr<GetPckCertificateResult> GetPckCertificate(
      const Ppid &ppid, const CpuSvn &cpu_svn, const PceSvn &pce_svn,
      const PceId &pce_id) = 0;

  // Retrieves X.509 SGX Provisioning Certification Key (PCK) certificates for
  // SGX-enabled platform for all configured TCB levels.
  virtual StatusOr<GetPckCertificatesResult> GetPckCertificates(
      const Ppid &ppid, const PceId &pce_id) = 0;

  // Retrieves X.509 Certificate Revocation List (CRL) with revoked SGX PCK
  // Certificates. The CRL returned is for the CA specified in |sgx_ca_type|.
  virtual StatusOr<GetCrlResult> GetCrl(SgxCaType sgx_ca_type) = 0;

  // Retrieves SGX TCB information for given FMSPC.
  virtual StatusOr<GetTcbInfoResult> GetTcbInfo(const Fmspc &fmspc) = 0;
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_SGX_PCS_CLIENT_H_
