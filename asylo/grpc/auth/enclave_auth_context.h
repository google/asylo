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

#ifndef ASYLO_GRPC_AUTH_ENCLAVE_AUTH_CONTEXT_H_
#define ASYLO_GRPC_AUTH_ENCLAVE_AUTH_CONTEXT_H_

#include <string>
#include <vector>

#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/identity/delegating_identity_expectation_matcher.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/util/statusor.h"
#include "include/grpcpp/server_context.h"

namespace asylo {

/// Encapsulates the authentication properties of an EKEP-based gRPC connection.
///
/// The authentication properties in an EnclaveAuthContext object include the
/// secure transport protocol and the peer's enclave identities.
///
/// Virtual functions are only for mocking.
class EnclaveAuthContext {
 public:
  /// Constructs an EnclaveAuthContext using the authentication properties from
  /// `server_context`.
  ///
  /// The resulting EnclaveAuthContext contains the authentication properties on
  /// the server-side of the connection.
  ///
  /// \param server_context The server's authentication context.
  static StatusOr<EnclaveAuthContext> CreateFromServerContext(
      const ::grpc::ServerContext &server_context);

  /// Creates an EnclaveAuthContext from the authentication properties in
  /// `auth_context`.
  ///
  /// \param auth_context An authentication context.
  static StatusOr<EnclaveAuthContext> CreateFromAuthContext(
      const ::grpc::AuthContext &auth_context);

  EnclaveAuthContext() = default;
  virtual ~EnclaveAuthContext() = default;

  /// Gets the secure transport record-protocol used for securing frames over
  /// the connection.
  ///
  /// \return The secure transport record-protocol.
  virtual RecordProtocol GetRecordProtocol() const;

  /// Indicates whether the authenticated peer has an identity matching
  /// `description`.
  ///
  /// \param description A description of the identity.
  /// \return True if the peer has the specified identity.
  virtual bool HasEnclaveIdentity(
      const EnclaveIdentityDescription &description) const;

  /// Finds and returns a peer identity matching `description`, if one exists.
  ///
  /// \param description A description of an identity to find.
  /// \return A pointer to the identity on success, and a StatusOr with a
  ///        `GoogleError::NOT_FOUND` Status on failure.
  virtual StatusOr<const EnclaveIdentity *> FindEnclaveIdentity(
      const EnclaveIdentityDescription &description) const;

  /// Evaluates the peer's identities against `acl`.
  ///
  /// \param acl The ACL against which to evaluate the peer's identities.
  /// \return A bool indicating whether the peer's identities match `acl`, or a
  ///         non-OK Status if an error occurred while evaluating the ACL.
  virtual StatusOr<bool> EvaluateAcl(const IdentityAclPredicate &acl) const;

  /// Evaluates the peer's identities against `acl`.
  ///
  /// \param acl The ACL against which to evaluate the peer's identities.
  /// \param[out] explanation An explanation of why the peer's identities did
  ///             not match `acl`, if the result is false.
  /// \return A bool indicating whether the peer's identities match `acl`, or a
  ///         non-OK Status if an error occurred while evaluating the ACL.
  virtual StatusOr<bool> EvaluateAcl(const IdentityAclPredicate &acl,
                                     std::string *explanation) const;

  /// Evaluates whether any of the peer's identities match `expectation`.
  ///
  /// \param expectation The expectation against which to evaluate the peer's
  ///                    identities.
  /// \return A bool indicating whether any of the peer's identities match
  ///         `expectation`, or a non-OK Status if an error occurred while
  ///         evaluating `expectation`.
  virtual StatusOr<bool> EvaluateAcl(
      const EnclaveIdentityExpectation &expectation) const;

  /// Evaluates whether any of the peer's identities match `expectation`.
  ///
  /// \param expectation The expectation against which to evaluate the peer's
  ///                    identities.
  /// \param[out] explanation An explanation of why the peer's identities did
  ///                         not match `expectation`, if the result is false.
  /// \return A bool indicating whether any of the peer's identities match
  ///         `expectation`, or a non-OK Status if an error occurred while
  ///         evaluating `expectation`.
  virtual StatusOr<bool> EvaluateAcl(
      const EnclaveIdentityExpectation &expectation,
      std::string *explanation) const;

 private:
  // Creates an EnclaveAuthContext for the given peer's |identities| and the
  // session |record_protocol|.
  EnclaveAuthContext(EnclaveIdentities identities,
                     RecordProtocol record_protocol);

  // Enclave identities held by the authenticated peer.
  std::vector<EnclaveIdentity> identities_;

  // Secure transport record protocol.
  RecordProtocol record_protocol_;

  // Matcher used to evaluate ACLs against the authenticated peer's identities.
  DelegatingIdentityExpectationMatcher matcher_;
};

}  // namespace asylo

#endif  // ASYLO_GRPC_AUTH_ENCLAVE_AUTH_CONTEXT_H_
