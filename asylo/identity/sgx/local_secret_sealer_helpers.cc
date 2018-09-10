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

#include "asylo/identity/sgx/local_secret_sealer_helpers.h"

#include <cstdint>

#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/sealed_secret.pb.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/identity/sgx/hardware_interface.h"
#include "asylo/identity/sgx/local_sealed_secret.pb.h"
#include "asylo/identity/sgx/self_identity.h"
#include "asylo/platform/common/singleton.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status_macros.h"

namespace asylo {
namespace sgx {
namespace internal {

const char *const kSgxLocalSecretSealerRootName = "SGX";

Status ParseKeyGenerationParamsFromSealedSecretHeader(
    const SealedSecretHeader &header, UnsafeBytes<kCpusvnSize> *cpusvn,
    CipherSuite *cipher_suite, CodeIdentityExpectation *sgx_expectation) {
  const SealingRootInformation &root_info = header.root_info();
  if (root_info.sealing_root_type() != LOCAL) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Incorrect sealing_root_type");
  }
  if (root_info.sealing_root_name() != kSgxLocalSecretSealerRootName) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Incorrect sealing_root_name");
  }
  SealedSecretAdditionalInfo info;
  if (!info.ParseFromString(root_info.additional_info())) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Could not parse additional_info");
  }
  if (info.cpusvn().size() != cpusvn->size()) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Incorrect cpusvn size");
  }
  cpusvn->assign(info.cpusvn().data(), info.cpusvn().size());
  if (!CipherSuite_IsValid(info.cipher_suite()) ||
      info.cipher_suite() == UNKNOWN_CIPHER_SUITE) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Unsupported cipher suite");
  }
  *cipher_suite = info.cipher_suite();
  if (header.client_acl().item_case() != IdentityAclPredicate::kExpectation) {
    return Status(::asylo::error::GoogleError::INVALID_ARGUMENT,
                  "Malformed client_acl");
  }
  const EnclaveIdentityExpectation &generic_expectation =
      header.client_acl().expectation();
  ASYLO_RETURN_IF_ERROR(
      ParseSgxExpectation(generic_expectation, sgx_expectation));
  bool result;
  ASYLO_ASSIGN_OR_RETURN(result,
                         MatchIdentityToExpectation(GetSelfIdentity()->identity,
                                                    *sgx_expectation));
  if (!result) {
    return Status(::asylo::error::GoogleError::PERMISSION_DENIED,
                  "Identity of the current enclave does not match the ACL");
  }
  return Status::OkStatus();
}

uint16_t ConvertMatchSpecToKeypolicy(const CodeIdentityMatchSpec &spec) {
  uint16_t policy = 0;
  if (spec.is_mrenclave_match_required()) {
    policy |= kKeypolicyMrenclaveBitMask;
  }
  if (spec.is_mrsigner_match_required()) {
    policy |= kKeypolicyMrsignerBitMask;
  }
  return policy;
}

Status GenerateCryptorKey(CipherSuite cipher_suite, const std::string &key_id,
                          const UnsafeBytes<kCpusvnSize> &cpusvn,
                          const CodeIdentityExpectation &sgx_expectation,
                          size_t key_size, CleansingVector<uint8_t> *key) {
  // The function generates the |key_size| number of bytes by concatenating
  // bytes from one or more hardware-generated "subkeys." Each of the subkeys
  // is obtained by calling the GetHardwareKey() function. Except for the last
  // subkey, all bytes from all other subkeys are utilized. If more than one
  // subkey is used, each subkey is generated using a different value of
  // the KEYID field of the KEYREQUEST input to the GetHardwareKey() function.
  // All the other fields of the KEYREQUEST structure stay unchanged across
  // the GetHardwareKey() calls.

  // Create and populate an aligned KEYREQUEST structure.
  AlignedKeyrequestPtr req;
  req->keyname = KeyrequestKeyname::SEAL_KEY;
  req->keypolicy = ConvertMatchSpecToKeypolicy(sgx_expectation.match_spec());
  req->isvsvn =
      sgx_expectation.reference_identity().signer_assigned_identity().isvsvn();
  req->reserved1.fill(0);
  req->cpusvn = cpusvn;
  ConvertSecsAttributeRepresentation(
      sgx_expectation.match_spec().attributes_match_mask(),
      &req->attributemask);
  // req->keyid is populated uniquely on each call to GetHardwareKey().
  req->miscmask = sgx_expectation.match_spec().miscselect_match_mask();
  req->reserved2.fill(0);

  // The |req->keyid| field is populated to uniquely identify each of the
  // hardware subkeys. This is done by constructing a sub-key-specific
  // |key_info| string, and hashing the contents of that string into
  // |req->key_id|.
  std::vector<ByteContainerView> serializer_input;

  // Description of the sealing root.
  std::string sealing_root_type_name = SealingRootType_Name(LOCAL);
  serializer_input.emplace_back(sealing_root_type_name);
  serializer_input.emplace_back(kSgxLocalSecretSealerRootName);

  // Cipher suite in which the key will be used.
  std::string cipher_suite_name = CipherSuite_Name(cipher_suite);
  serializer_input.emplace_back(cipher_suite_name);

  // Identifier of the key.
  serializer_input.emplace_back(key_id);

  // Size of the key.
  std::string key_size_str = ::absl::StrCat(key_size);
  serializer_input.emplace_back(key_size_str);

  key->resize(0);
  key->reserve(key_size);

  size_t remaining_key_bytes = key_size;
  size_t key_subscript = 0;
  std::string key_subscript_str = ::absl::StrCat(key_subscript);
  serializer_input.emplace_back(key_subscript_str);
  while (remaining_key_bytes > 0) {
    std::basic_string<uint8_t> key_info;
    ASYLO_RETURN_IF_ERROR(SerializeByteContainers(serializer_input, &key_info));
    static_assert(decltype(req->keyid)::size() == SHA256_DIGEST_LENGTH,
                  "KEYREQUEST.KEYID field has unexpected size");

    SHA256(key_info.data(), key_info.size(), req->keyid.data());

    AlignedHardwareKeyPtr hardware_key;
    if (!GetHardwareKey(*req, hardware_key.get())) {
      return Status(::asylo::error::GoogleError::INTERNAL,
                    "Could not get required hardware key");
    }
    size_t copy_size = std::min(hardware_key->size(), remaining_key_bytes);
    remaining_key_bytes -= copy_size;
    std::copy(hardware_key->cbegin(), hardware_key->cbegin() + copy_size,
              std::back_inserter(*key));
    ++key_subscript;
    key_subscript_str = ::absl::StrCat(key_subscript);
    serializer_input.back() = key_subscript_str;
  }
  return Status::OkStatus();
}

}  // namespace internal
}  // namespace sgx
}  // namespace asylo
