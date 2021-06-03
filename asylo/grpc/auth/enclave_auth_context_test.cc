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

#include "asylo/grpc/auth/enclave_auth_context.h"

#include <string>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/util/message_differencer.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/grpc/auth/core/enclave_grpc_security_constants.h"
#include "asylo/grpc/auth/core/handshake.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/named_identity_expectation_matcher.h"
#include "asylo/platform/common/static_map.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "src/core/lib/gprpp/ref_counted_ptr.h"
#include "src/core/lib/security/context/security_context.h"
#include "src/cpp/common/secure_auth_context.h"

namespace asylo {
namespace {

constexpr char kIdentity[] = "Identity";
constexpr char kMatchSpec1[] = "Identity";
constexpr char kMatchSpec2[] = "Foobar";
constexpr char kIdentityMismatchError[] = "Identity != Match spec";
constexpr char kAuthorityType1[] = "Good Authority";
constexpr char kAuthorityType2[] = "Bad Authority";

using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;

class TestIdentityExpectationMatcher : public NamedIdentityExpectationMatcher {
 public:
  StatusOr<bool> MatchAndExplain(const EnclaveIdentity &identity,
                                 const EnclaveIdentityExpectation &expectation,
                                 std::string *explanation) const override {
    if (identity.identity() != expectation.match_spec()) {
      if (explanation != nullptr) {
        *explanation = kIdentityMismatchError;
      }
      return false;
    }
    return true;
  }

  EnclaveIdentityDescription Description() const override {
    EnclaveIdentityDescription description;
    description.set_identity_type(EnclaveIdentityType::CODE_IDENTITY);
    description.set_authority_type(kAuthorityType1);
    return description;
  }
};

SET_STATIC_MAP_VALUE_OF_DERIVED_TYPE(IdentityExpectationMatcherMap,
                                     TestIdentityExpectationMatcher);

class EnclaveAuthContextTest : public ::testing::Test {
 protected:
  EnclaveAuthContextTest()
      : secure_auth_context_(absl::make_unique<::grpc::SecureAuthContext>(
            grpc_core::MakeRefCounted<grpc_auth_context>(/*chained=*/nullptr)
                .get())) {}

  void SetUp() override {
    good_identity_description_.set_identity_type(
        EnclaveIdentityType::CODE_IDENTITY);
    good_identity_description_.set_authority_type(kAuthorityType1);

    bad_identity_description_.set_identity_type(
        EnclaveIdentityType::CERT_IDENTITY);
    bad_identity_description_.set_authority_type(kAuthorityType2);

    EnclaveIdentity *identity = identities_.add_identities();
    identity->set_identity(kIdentity);
    *identity->mutable_description() = good_identity_description_;

    // Set default properties for a valid secure auth context.
    AddEnclaveIdentitiesProperty(identities_, secure_auth_context_.get());
    AddRecordProtocolProperty(RecordProtocol::ALTSRP_AES128_GCM,
                              secure_auth_context_.get());
    AddTransportSecurityTypeProperty(secure_auth_context_.get());
  }

  // Adds a record protocol property to |secure_auth_context| with
  // |record_protocol| as the value.
  void AddRecordProtocolProperty(
      RecordProtocol record_protocol,
      ::grpc::SecureAuthContext *secure_auth_context) {
    std::vector<uint8_t> serialized_record_protocol(sizeof(record_protocol));
    google::protobuf::io::CodedOutputStream::WriteLittleEndian32ToArray(
        record_protocol, serialized_record_protocol.data());
    std::string record_protocol_str(
        reinterpret_cast<const char *>(serialized_record_protocol.data()),
        serialized_record_protocol.size());
    secure_auth_context_->AddProperty(
        GRPC_ENCLAVE_RECORD_PROTOCOL_PROPERTY_NAME, record_protocol_str);
  }

  // Adds a identities proto property to |secure_auth_context| containing the
  // given |identities| proto and sets this property to be the peer identity
  // property.
  void AddEnclaveIdentitiesProperty(
      const EnclaveIdentities &identities,
      ::grpc::SecureAuthContext *secure_auth_context) {
    std::string serialized_identities;
    ASSERT_TRUE(identities.SerializeToString(&serialized_identities));
    secure_auth_context->AddProperty(
        GRPC_ENCLAVE_IDENTITIES_PROTO_PROPERTY_NAME, serialized_identities);
    secure_auth_context->SetPeerIdentityPropertyName(
        GRPC_ENCLAVE_IDENTITIES_PROTO_PROPERTY_NAME);
  }

  // Adds a transport security type property to |secure_auth_context| with the
  // value GRPC_ENCLAVE_TRANSPORT_SECURITY_TYPE.
  void AddTransportSecurityTypeProperty(
      ::grpc::SecureAuthContext *secure_auth_context) {
    secure_auth_context->AddProperty(GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME,
                                     GRPC_ENCLAVE_TRANSPORT_SECURITY_TYPE);
  }

  EnclaveIdentityDescription good_identity_description_;
  EnclaveIdentityDescription bad_identity_description_;
  std::unique_ptr<::grpc::SecureAuthContext> secure_auth_context_;
  EnclaveIdentities identities_;
};

// Verify that an EnclaveAuthContext can be created successfully from a valid
// auth context.
TEST_F(EnclaveAuthContextTest, CreateSuccess) {
  EXPECT_THAT(EnclaveAuthContext::CreateFromAuthContext(*secure_auth_context_),
              IsOk());
}

// Verify that CreateFromAuthContext() fails when the auth context does not have
// a valid peer identity proto.
TEST_F(EnclaveAuthContextTest, CreateFailsBadIdentityProto) {
  ::grpc::SecureAuthContext secure_auth_context(
      grpc_core::MakeRefCounted<grpc_auth_context>(/*chained=*/nullptr).get());
  AddRecordProtocolProperty(RecordProtocol::ALTSRP_AES128_GCM,
                            &secure_auth_context);
  AddTransportSecurityTypeProperty(&secure_auth_context);

  // Set the peer identity property to contain a value that cannot be
  // deserialized to an EnclaveIdentities proto.
  secure_auth_context.AddProperty(GRPC_ENCLAVE_IDENTITIES_PROTO_PROPERTY_NAME,
                                  "foobar");

  EXPECT_THAT(EnclaveAuthContext::CreateFromAuthContext(secure_auth_context),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify that CreateFromAuthContext() fails when the auth context has an
// invalid transport security type.
TEST_F(EnclaveAuthContextTest, CreateFailsBadTransportSecurityType) {
  ::grpc::SecureAuthContext secure_auth_context(
      grpc_core::MakeRefCounted<grpc_auth_context>(/*chained=*/nullptr).get());
  AddRecordProtocolProperty(RecordProtocol::ALTSRP_AES128_GCM,
                            &secure_auth_context);
  AddEnclaveIdentitiesProperty(identities_, &secure_auth_context);

  // Set the transport security property to contain an invalid value.
  secure_auth_context.AddProperty(GRPC_TRANSPORT_SECURITY_TYPE_PROPERTY_NAME,
                                  "foobar");

  EXPECT_THAT(EnclaveAuthContext::CreateFromAuthContext(secure_auth_context),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify that CreateFromAuthContext() fails when the auth context has an
// unrecognized auth property.
TEST_F(EnclaveAuthContextTest, CreateFailsUnrecognizedAuthProperty) {
  // Add an unrecognized property.
  secure_auth_context_->AddProperty("foo property", "foobar");

  EXPECT_THAT(EnclaveAuthContext::CreateFromAuthContext(*secure_auth_context_),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify that CreateFromAuthContext() fails when the auth context does not
// represent an authenticated peer.
TEST_F(EnclaveAuthContextTest, CreateFailsPeerUnauthenticated) {
  // Create a SecureAuthContext that does not have a peer identity property.
  // This is considered to be an unauthenticated peer.
  ::grpc::SecureAuthContext secure_auth_context(
      grpc_core::MakeRefCounted<grpc_auth_context>(/*chained=*/nullptr).get());

  EXPECT_THAT(EnclaveAuthContext::CreateFromAuthContext(secure_auth_context),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify that HasEnclaveIdentity() works as expected for identities that are
// present in the peer and identities that are not present.
TEST_F(EnclaveAuthContextTest, HasEnclaveIdentity) {
  EnclaveAuthContext auth_context;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      auth_context,
      EnclaveAuthContext::CreateFromAuthContext(*secure_auth_context_));

  EXPECT_TRUE(auth_context.HasEnclaveIdentity(good_identity_description_));
  EXPECT_FALSE(auth_context.HasEnclaveIdentity(bad_identity_description_));
}

// Verify that FindEnclaveIdentity() retrieves an EnclaveIdentity when the
// requested identity is present.
TEST_F(EnclaveAuthContextTest, FindEnclaveIdentitySuccess) {
  EnclaveAuthContext auth_context;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      auth_context,
      EnclaveAuthContext::CreateFromAuthContext(*secure_auth_context_));

  StatusOr<const EnclaveIdentity *> identity_result =
      auth_context.FindEnclaveIdentity(good_identity_description_);
  ASSERT_THAT(identity_result, IsOk());

  const EnclaveIdentity *identity = identity_result.value();
  EXPECT_EQ(identity->identity(), kIdentity);
  EXPECT_THAT(identity->description(), EqualsProto(good_identity_description_));
}

// Verify that FindEnclaveIdentity() returns NOT_FOUND if the requested
// EnclaveIdentity is not present.
TEST_F(EnclaveAuthContextTest, FindEnclaveIdentityNotFound) {
  EnclaveAuthContext auth_context;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      auth_context,
      EnclaveAuthContext::CreateFromAuthContext(*secure_auth_context_));

  StatusOr<const EnclaveIdentity *> identity_result =
      auth_context.FindEnclaveIdentity(bad_identity_description_);

  EXPECT_THAT(auth_context.FindEnclaveIdentity(bad_identity_description_),
              StatusIs(absl::StatusCode::kNotFound));
}

// Verify that GetRecordProtocol() returns the record protocol.
TEST_F(EnclaveAuthContextTest, GetRecordProtocol) {
  EnclaveAuthContext auth_context;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      auth_context,
      EnclaveAuthContext::CreateFromAuthContext(*secure_auth_context_));

  EXPECT_EQ(auth_context.GetRecordProtocol(),
            RecordProtocol::ALTSRP_AES128_GCM);
}

// Verify that EvaluateAcl() returns a non-OK Status when there is an error in
// ACL evaluation.
TEST_F(EnclaveAuthContextTest, EvaluateAclError) {
  EnclaveAuthContext auth_context;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      auth_context,
      EnclaveAuthContext::CreateFromAuthContext(*secure_auth_context_));

  // No IdentityExpectationMatcher exists for |bad_identity_description_|.
  IdentityAclPredicate acl;
  EnclaveIdentityExpectation *expectation = acl.mutable_expectation();
  *expectation->mutable_reference_identity()->mutable_description() =
      bad_identity_description_;
  expectation->set_match_spec(kMatchSpec1);

  // Test the IdentityAclPredicate overload.
  {
    std::string explanation;
    ASSERT_THAT(auth_context.EvaluateAcl(acl, &explanation), Not(IsOk()));
    EXPECT_THAT(explanation, IsEmpty());
  }

  // Test the EnclaveIdentityExpectation overload.
  {
    std::string explanation;
    ASSERT_THAT(auth_context.EvaluateAcl(acl.expectation(), &explanation),
                Not(IsOk()));
    EXPECT_THAT(explanation, IsEmpty());
  }
}

// Verify that EvaluateAcl() returns false and populates the explanation string
// when the peer's identities do not match the ACL.
TEST_F(EnclaveAuthContextTest, EvaluateAclFailure) {
  EnclaveAuthContext auth_context;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      auth_context,
      EnclaveAuthContext::CreateFromAuthContext(*secure_auth_context_));

  // The ACL does not match the peer's identities.
  IdentityAclPredicate acl;
  EnclaveIdentityExpectation *expectation = acl.mutable_expectation();
  *expectation->mutable_reference_identity()->mutable_description() =
      good_identity_description_;
  expectation->set_match_spec(kMatchSpec2);

  // Test the IdentityAclPredicate overload.
  {
    std::string explanation;
    ASSERT_THAT(auth_context.EvaluateAcl(acl, &explanation),
                IsOkAndHolds(false));
    EXPECT_THAT(explanation, HasSubstr(kIdentityMismatchError));
  }

  // Test the EnclaveIdentityExpectation overload.
  {
    std::string explanation;
    ASSERT_THAT(auth_context.EvaluateAcl(acl.expectation(), &explanation),
                IsOkAndHolds(false));
    EXPECT_THAT(explanation, HasSubstr(kIdentityMismatchError));
  }
}

// Verify that EvaluateAcl() returns true when the ACL passes.
TEST_F(EnclaveAuthContextTest, EvaluateAclSuccess) {
  EnclaveAuthContext auth_context;
  ASYLO_ASSERT_OK_AND_ASSIGN(
      auth_context,
      EnclaveAuthContext::CreateFromAuthContext(*secure_auth_context_));

  // The ACL matches the client's identities.
  IdentityAclPredicate acl;
  EnclaveIdentityExpectation *expectation = acl.mutable_expectation();
  *expectation->mutable_reference_identity()->mutable_description() =
      good_identity_description_;
  expectation->set_match_spec(kMatchSpec1);

  // Test the IdentityAclPredicate overload.
  {
    std::string explanation;
    ASSERT_THAT(auth_context.EvaluateAcl(acl, &explanation),
                IsOkAndHolds(true));
    EXPECT_THAT(explanation, IsEmpty());
  }

  // Test the EnclaveIdentityExpectation overload.
  {
    std::string explanation;
    ASSERT_THAT(auth_context.EvaluateAcl(acl.expectation(), &explanation),
                IsOkAndHolds(true));
    EXPECT_THAT(explanation, IsEmpty());
  }
}

}  // namespace
}  // namespace asylo
