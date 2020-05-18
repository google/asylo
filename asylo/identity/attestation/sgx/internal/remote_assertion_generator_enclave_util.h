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

#ifndef ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_REMOTE_ASSERTION_GENERATOR_ENCLAVE_UTIL_H_
#define ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_REMOTE_ASSERTION_GENERATOR_ENCLAVE_UTIL_H_

#include <memory>
#include <string>
#include <vector>

#include <google/protobuf/repeated_field.h>
#include "absl/strings/string_view.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/ecdsa_p256_sha256_signing_key.h"
#include "asylo/crypto/keys.pb.h"
#include "asylo/crypto/signing_key.h"
#include "asylo/identity/attestation/sgx/internal/attestation_key.pb.h"
#include "asylo/identity/attestation/sgx/internal/remote_assertion_generator_enclave.pb.h"
#include "asylo/identity/attestation/sgx/internal/sgx_remote_assertion_generator_impl.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/sealing/sealed_secret.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/grpcpp.h"

namespace asylo {
namespace sgx {

// Checks that the sealed secret header contains correct name, version, and
// purpose.
Status CheckRemoteAssertionGeneratorEnclaveSecretHeader(
    const SealedSecretHeader &header);

// Creates a SealedSecretHeader and sets its name, version and purpose to
// correct values for an AGE secret header.
SealedSecretHeader GetRemoteAssertionGeneratorEnclaveSecretHeader();

// Creates a RemoteAssertionGeneratorEnclaveSecret that contains
// |attestation_key| and |certificate_chains|.
StatusOr<SealedSecret> CreateSealedSecret(
    const SealedSecretHeader &header,
    const google::protobuf::RepeatedPtrField<CertificateChain> &certificate_chains,
    const SigningKey &attestation_key);

// Unseals |sealed_secret| to get an attestation key and certificate chains.
// Assigns certificate chains to |certificate_chains| and then returns
// the attestation key. If there was an error happened during the process, a
// non-OK status is returned, and any certificate chain in |certificate_chains|
// is considered as invalid and should not be used.
StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>>
ExtractAttestationKeyAndCertificateChainsFromSealedSecret(
    const SealedSecret &sealed_secret,
    std::vector<CertificateChain> *certificate_chains);

// Extracts an attestation key from |asymmetric_signing_key_proto| and then
// returns the attestation key.
StatusOr<std::unique_ptr<EcdsaP256Sha256SigningKey>>
ExtractAttestationKeyFromAsymmetricSigningKeyProto(
    const AsymmetricSigningKeyProto &asymmetric_signing_key_proto);

// Creates and returns an AsymmetricSigningKeyProto from |attestation_key|.
StatusOr<AsymmetricSigningKeyProto> GetAsymmetricSigningKeyProtoFromSigningKey(
    const SigningKey &signing_key);

// Creates and returns a serialized PceSignReportPayload from |verifying_key|.
StatusOr<std::string> CreateSerializedPceSignReportPayloadFromVerifyingKey(
    const VerifyingKey &verifying_key);

// Creates and returns a REPORTDATA on |serialized_pce_sign_report_payload| that
// is suitable for the PCE's SignReport protocol.
StatusOr<Reportdata> GenerateReportdataForPceSignReportProtocol(
    absl::string_view serialized_pce_sign_report_payload);

// Creates and Starts a gRPC server that implements the methods declared by
// |remote_assertion_generator_service| on
// |remote_assertion_generator_server_address|. This function does not take
// ownership of |remote_assertion_generator_service|, and
// |remote_assertion_generator_service| must out-live the returned server
// object.
StatusOr<std::unique_ptr<::grpc::Server>> CreateAndStartServer(
    std::string remote_assertion_generator_server_address,
    SgxRemoteAssertionGeneratorImpl *remote_assertion_generator_service);

// Checks that each chain in |certificate_chains| passes the following checks:
// 1) The subject key of the end-entity certificate is |attestation_public_key|.
// 2) The certificate chain is valid.
Status CheckCertificateChainsForAttestationPublicKey(
    const VerifyingKey &attestation_public_key,
    const google::protobuf::RepeatedPtrField<CertificateChain> &certificate_chains,
    const CertificateFactoryMap &certificate_factories,
    const VerificationConfig &verification_config);

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_ATTESTATION_SGX_INTERNAL_REMOTE_ASSERTION_GENERATOR_ENCLAVE_UTIL_H_
