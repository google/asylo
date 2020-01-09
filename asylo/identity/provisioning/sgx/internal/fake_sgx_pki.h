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

#ifndef ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_FAKE_SGX_PKI_H_
#define ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_FAKE_SGX_PKI_H_

#include "absl/strings/string_view.h"

namespace asylo {
namespace sgx {

// Represents an X.509 certificate and its subject's private key. Should only be
// used to store data with a static lifetime.
struct CertificateAndPrivateKey {
  // A PEM-encoded X.509 certificate.
  absl::string_view certificate_pem;

  // The PEM-encoded ECDSA-P256 private key whose corresponding public key is
  // the subject public key in |certificate_pem|.
  absl::string_view signing_key_pem;
};

// The fake SGX Root CA certificate and private key.
extern const CertificateAndPrivateKey kFakeSgxRootCa;

// The fake SGX Platform CA certificate and private key.
extern const CertificateAndPrivateKey kFakeSgxPlatformCa;

// The fake SGX Processor CA certificate and private key.
extern const CertificateAndPrivateKey kFakeSgxProcessorCa;

// The fake SGX TCB Signing certificate and private key.
extern const CertificateAndPrivateKey kFakeSgxTcbSigner;

// A PEM-encoded ECDSA-P256 private key that can be used as the PCK for fake
// SGX platforms in tests.
extern const absl::string_view kFakePckPem;

// The PEM-encoded ECDSA-P256 public key corresponding to kFakePckPem.
extern const absl::string_view kFakePckPublicPem;

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PROVISIONING_SGX_INTERNAL_FAKE_SGX_PKI_H_
