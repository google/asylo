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

#ifndef ASYLO_IDENTITY_ENCLAVE_ASSERTION_AUTHORITY_H_
#define ASYLO_IDENTITY_ENCLAVE_ASSERTION_AUTHORITY_H_

#include <string>

#include "asylo/crypto/util/byte_container_util.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {

/// An EnclaveAssertionAuthority is an authority for assertions of a particular
/// identity type. An EnclaveAssertionAuthority is also identified by its
/// authority type. The combination of identity type and authority type uniquely
/// identifies an EnclaveAssertionAuthority.
///
/// EnclaveAssertionAuthority cannot be instantiated. It is an abstract
/// interface that is intended to be extended by subclasses that define a
/// particular set of operations on assertion authorities.
///
/// See EnclaveAssertionGenerator and EnclaveAssertionVerifier for examples of
/// how the EnclaveAssertionAuthority interface can be extended.
class EnclaveAssertionAuthority {
 public:
  virtual ~EnclaveAssertionAuthority() = default;

  /// Initializes this assertion authority using the provided `config`.
  ///
  /// \param config A config with which to initialize this authority.
  /// \return A Status indicating whether initialization succeeded.
  virtual Status Initialize(const std::string &config) = 0;

  /// Indicates whether this assertion authority has been initialized
  /// successfully via a call to Initialize().
  ///
  /// \return True if this authority is initialized.
  virtual bool IsInitialized() const = 0;

  /// Gets the enclave identity type handled by this assertion authority.
  ///
  /// \return The identity type handled by this authority.
  virtual EnclaveIdentityType IdentityType() const = 0;

  /// Gets the type of this assertion authority.
  ///
  /// \return The type of this authority.
  virtual std::string AuthorityType() const = 0;

  /// Gets a unique identifier for an EnclaveAssertionAuthority with the given
  /// `identity_type` and `authority_type`.
  ///
  /// The identifier is a string that combines `identity_type` and
  /// `authority_type`. It can be used as a unique identifier for an authority
  /// that handles assertions for `identity_type` and `authority_type`.
  ///
  /// \param identity_type The identity type handled by the authority.
  /// \param authority_type The authority type of the authority.
  /// \return The generated authority identifier on success, or a non-OK
  ///         Status on failure.
  static StatusOr<std::string> GenerateAuthorityId(
      const EnclaveIdentityType &identity_type,
      const std::string &authority_type) {
    std::string serialized;
    ASYLO_RETURN_IF_ERROR(asylo::SerializeByteContainers(
        &serialized, EnclaveIdentityType_Name(identity_type), authority_type));
    return serialized;
  }

 protected:
  /// Indicates whether `description` describes an assertion that is compatible
  /// with this authority.
  ///
  /// This functionality is common to all assertion authorities and is provided
  /// for convenience of implementing more complex operations.
  ///
  /// \param description A description to check for compatibility.
  /// \return True if `description` is compatible with this authority.
  bool IsCompatibleAssertionDescription(
      const AssertionDescription &description) const {
    return (description.identity_type() == IdentityType()) &&
           (description.authority_type() == AuthorityType());
  }
};

}  // namespace asylo

#endif  // ASYLO_IDENTITY_ENCLAVE_ASSERTION_AUTHORITY_H_
