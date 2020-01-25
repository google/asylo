/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/identity/attestation/sgx/internal/certificate_util.h"

#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key_certificate_impl.h"

namespace asylo {
namespace sgx {

const CertificateFactoryMap *GetSgxCertificateFactories() {
  static const CertificateFactoryMap *kSgxCertificateFactories =
      new CertificateFactoryMap(
          {{Certificate::X509_DER, X509Certificate::Create},
           {Certificate::X509_PEM, X509Certificate::Create},
           {Certificate::SGX_ATTESTATION_KEY_CERTIFICATE,
            AttestationKeyCertificateImpl::Create}});
  return kSgxCertificateFactories;
}

}  // namespace sgx
}  // namespace asylo
