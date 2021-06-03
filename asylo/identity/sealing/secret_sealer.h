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

#ifndef ASYLO_IDENTITY_SEALING_SECRET_SEALER_H_
#define ASYLO_IDENTITY_SEALING_SECRET_SEALER_H_

#include <cstdint>
#include <string>
#include <vector>

#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/sealing/sealed_secret.pb.h"
#include "asylo/platform/common/static_map.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {

class SecretSealer {
 public:
  SecretSealer() = default;
  virtual ~SecretSealer() = default;

  /// Gets the sealing root type of this SecretSealer.
  ///
  /// \return The sealing root type of this class.
  virtual SealingRootType RootType() const = 0;

  /// Gets the sealing root name of this SecretSealer.
  ///
  /// \return The sealing root name of this class.
  virtual std::string RootName() const = 0;

  /// Gets the sealing root ACL of this SecretSealer.
  ///
  /// \return The sealing root ACL of this object.
  virtual std::vector<EnclaveIdentityExpectation> RootAcl() const = 0;

  /// Generates the default sealed-secret header based on the configuration of
  /// the SecretSealer and writes it to `header`.
  ///
  /// \param[out] header The destination for the default SealedSecretHeader
  ///             value.
  /// \return A non-OK status if a default cannot be set.
  virtual Status SetDefaultHeader(SealedSecretHeader *header) const = 0;

  /// Gets the maximum message size (in bytes) that can be sealed according to
  /// the cipher-suite configuration recorded in `header`.
  ///
  /// The user is expected to call this before calling Seal() to ensure that
  /// they have chunked their messages correctly. The maximum message sizes of
  /// supported cipher-suites are as follows:
  /// - AES-GCM-SIV supports a maximum message size of 32 MiB
  ///
  /// \param header The associated header to determine the maximum message size.
  /// \return The maximum message size that can be encrypted based on the
  ///         cipher-suite configuration in header, or a non-OK status if the
  //          cipher-suite configuration is not supported.
  virtual StatusOr<size_t> MaxMessageSize(
      const SealedSecretHeader &header) const = 0;

  /// Gets the maximum number of messages that can safely be sealed according to
  /// the cipher-suite configuration recorded in `header`.
  ///
  /// The user is responsible for following these guidelines. The secret sealer
  /// will not check the number of secrets sealed. The maximum number of sealed
  /// messages of supported cipher-suites are as follows:
  /// - AES-GCM-SIV can safely seal 2 ^ 48 messages
  ///
  /// \param header The associated header to determine the maximum number of
  ///        sealed messages.
  /// \return The maximum number of messages that can be sealed  based on the
  ///         cipher-suite configuration in header, or a non-OK status if the
  ///         cipher-suite configuration is not supported.
  virtual StatusOr<uint64_t> MaxSealedMessages(
      const SealedSecretHeader &header) const = 0;

  /// Seals the input per the header specification.
  ///
  /// The `header` must have its `secret_name`, `secret_version` and
  /// `secret_purpose` fields populated. If any of the remaining fields in the
  /// `header` are populated, then they must be compatible with the underlying
  /// sealing root.
  ///
  /// \param header The metadata to guide the sealing.
  /// \param additional_authenticated_data Unencrypted data that is bundled with
  ///        the sealed secret.
  /// \param secret The data to encrypt and seal.
  /// \param[out] sealed_secret The output sealed secret.
  /// \return A non-OK status if sealing fails.
  virtual Status Seal(const SealedSecretHeader &header,
                      ByteContainerView additional_authenticated_data,
                      ByteContainerView secret,
                      SealedSecret *sealed_secret) = 0;

  /// Unseals the `sealed_secret` and writes it to `secret`.
  ///
  /// \param sealed_secret The input secret to unseal.
  /// \param[out] secret The destination for the unsealed secret.
  /// \return A non-OK Status if unsealing fails.
  virtual Status Unseal(const SealedSecret &sealed_secret,
                        CleansingVector<uint8_t> *secret) = 0;

  /// Re-seals an already sealed secret to a new header.
  ///
  /// The net effect of calling this method is same as unsealing the secret and
  /// then sealing it to the new header, and that is exactly how this method is
  /// implemented by the base class. A derived class of SecretSealer may choose
  /// to further optimize this method.
  ///
  /// \param old_sealed_secret The sealed secret to re-seal.
  /// \param new_header The metadata to guide the re-sealing.
  /// \param[out] new_sealed_secret The output sealed secret.
  /// \return A non-OK status if re-sealing fails.
  virtual Status Reseal(const SealedSecret &old_sealed_secret,
                        const SealedSecretHeader &new_header,
                        SealedSecret *new_sealed_secret);

  /// Combines the specified sealing root type and sealing root name
  /// to form a string. The combined string uniquely identifies the SecretSealer
  /// responsible for handling secrets associated with the particular
  /// combination of root-type `type` and root-name `name`.
  ///
  /// \param type The root type for sealing (e.g., from RootType()).
  /// \param name The root name for sealing (e.g., from RootName()).
  /// \return An object that represents a result string, or a failure status.
  static StatusOr<std::string> GenerateSealerId(SealingRootType type,
                                                const std::string &name);
};

/// \cond Internal
template <>
struct Namer<SecretSealer> {
  std::string operator()(const SecretSealer &sealer) {
    return SecretSealer::GenerateSealerId(sealer.RootType(), sealer.RootName())
        .value();
  }
};

DEFINE_STATIC_MAP_OF_BASE_TYPE(SecretSealerMap, SecretSealer)
/// \endcond

}  // namespace asylo

#endif  // ASYLO_IDENTITY_SEALING_SECRET_SEALER_H_
