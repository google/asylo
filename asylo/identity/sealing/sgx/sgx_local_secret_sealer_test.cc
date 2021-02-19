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

#include "asylo/identity/sealing/sgx/sgx_local_secret_sealer.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <memory>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/flags/flag.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "asylo/crypto/algorithms.pb.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/fake_enclave.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/proto_format.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/identity/platform/sgx/internal/self_identity.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/sealing/sealed_secret.pb.h"
#include "asylo/identity/sealing/sgx/internal/local_secret_sealer_helpers.h"
#include "asylo/identity/sealing/sgx/internal/local_secret_sealer_test_data.pb.h"
#include "asylo/platform/common/singleton.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/path.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

ABSL_FLAG(std::string, test_data_path, "", "Path to secret sealer test data");

namespace asylo {
namespace {

using ::testing::Not;

constexpr char kBadRootName[] = "BAD";
constexpr char kBadExpectation[] = "BAD";
constexpr char kTestString[] = "test";
constexpr char kTestAad[] = "Mary had a little lamb";
constexpr char kTestSecret[] = "Its fleece was white as snow";
constexpr size_t kTestSecretSize = sizeof(kTestSecret) - 1;

// A test fixture is used for initializing state that is commonly used across
// different tests.
class SgxLocalSecretSealerTest : public ::testing::Test {
 protected:
  SgxLocalSecretSealerTest() {
    do {
      // Construct a random fake enclave with ISVSVN less than max possible
      // value for ISVSVN.
      enclave_.reset(sgx::RandomFakeEnclaveFactory::Construct());
    } while (enclave_->get_isvsvn() == 0xFFFF);
    sgx::FakeEnclave::EnterEnclave(*enclave_);

    // Construct a fake enclave that differs from enclave_ only in MRENCLAVE.
    // A secret sealed to MRENCLAVE from enclave_ cannot be unsealed by
    // enclave_copy_different_mrenclave_.
    enclave_copy_different_mrenclave_ =
        absl::make_unique<sgx::FakeEnclave>(*enclave_);
    enclave_copy_different_mrenclave_->set_mrenclave(
        TrivialRandomObject<UnsafeBytes<kSha256DigestLength>>());

    // Construct a fake enclave that differs from enclave_ only in MRSIGNER.
    // A secret sealed to MRSIGNER from enclave_ cannot be unsealed by
    // enclave_copy_different_mrsigner_.
    enclave_copy_different_mrsigner_ =
        absl::make_unique<sgx::FakeEnclave>(*enclave_);
    enclave_copy_different_mrsigner_->set_mrsigner(
        TrivialRandomObject<UnsafeBytes<kSha256DigestLength>>());

    // Construct a fake enclave that has ISVSVN value 1 greater than that of
    // enclave_. A secret sealed to MRSIGNER from enclave_ can be unsealed
    // by enclave_copy_higher_isvsvn_. However, a secret sealed to MRSIGNER from
    // enclave_copy_higher_isvsvn_ cannot be unsealed by enclave_.
    enclave_copy_higher_isvsvn_ =
        absl::make_unique<sgx::FakeEnclave>(*enclave_);
    enclave_copy_higher_isvsvn_->set_isvsvn(enclave_->get_isvsvn() + 1);
  }

  ~SgxLocalSecretSealerTest() override { sgx::FakeEnclave::ExitEnclave(); }

  void PrepareSealedSecretHeader(const SgxLocalSecretSealer &sealer,
                                 SealedSecretHeader *header) {
    ASSERT_THAT(sealer.SetDefaultHeader(header), IsOk());
    header->set_secret_name(kTestString);
    header->set_secret_version(kTestString);
    header->set_secret_purpose(kTestString);
    header->set_secret_handling_policy(kTestString);
  }

  std::unique_ptr<sgx::FakeEnclave> enclave_;
  std::unique_ptr<sgx::FakeEnclave> enclave_copy_different_mrenclave_;
  std::unique_ptr<sgx::FakeEnclave> enclave_copy_different_mrsigner_;
  std::unique_ptr<sgx::FakeEnclave> enclave_copy_higher_isvsvn_;
};

TEST_F(SgxLocalSecretSealerTest, VerifyRootType) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  EXPECT_EQ(sealer->RootType(), LOCAL);

  sealer = SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  EXPECT_EQ(sealer->RootType(), LOCAL);
}

TEST_F(SgxLocalSecretSealerTest, VerifyRootName) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  EXPECT_EQ(sealer->RootName(), sgx::internal::kSgxLocalSecretSealerRootName);

  sealer = SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  EXPECT_EQ(sealer->RootName(), sgx::internal::kSgxLocalSecretSealerRootName);
}

TEST_F(SgxLocalSecretSealerTest, VerifyRootAcl) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  EXPECT_TRUE(sealer->RootAcl().empty());

  sealer = SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  EXPECT_TRUE(sealer->RootAcl().empty());
}

// Verify that SetDefaultHeader() sets the reference identity in the header to
// the current enclave's identity.
TEST_F(SgxLocalSecretSealerTest, VerifyDefaultHeaderReferenceIdentity) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);
  SgxIdentity reference_identity;
  ASYLO_ASSERT_OK(sgx::ParseSgxIdentity(
      header.client_acl().expectation().reference_identity(),
      &reference_identity));

  SgxIdentity current_identity =
      sgx::FakeEnclave::GetCurrentEnclave()->GetIdentity();
  EXPECT_THAT(reference_identity, EqualsProto(current_identity));
}

// Verify that ParseKeyGenerationParamsFromSealedSecretHeader() fails when the
// root type in the header is incorrect.
TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsBadSealingRootType) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);
  header.mutable_root_info()->set_sealing_root_type(REMOTE);

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &aead_scheme, &sgx_expectation),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify that ParseKeyGenerationParamsFromSealedSecretHeader() fails when the
// root name in the header is incorrect.
TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsBadSealingRootName) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);
  header.mutable_root_info()->set_sealing_root_name(kBadRootName);

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &aead_scheme, &sgx_expectation),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsBadAeadScheme) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);
  header.mutable_root_info()->set_aead_scheme(AeadScheme::UNKNOWN_AEAD_SCHEME);

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &aead_scheme, &sgx_expectation),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify that ParseKeyGenerationParamsFromSealedSecretHeader() fails when the
// client acl does not have correct format.
TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsBadClientAcl) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);
  header.mutable_client_acl()
      ->mutable_expectation()
      ->mutable_reference_identity()
      ->set_identity(kBadExpectation);

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &aead_scheme, &sgx_expectation),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify that the default SealedSecretHeader that binds a secret to MRENCLAVE
// can be parsed from the same enclave.
TEST_F(SgxLocalSecretSealerTest,
       ParseKeyGenerationParamsMrenclaveSuccessSameEnclave) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &aead_scheme, &sgx_expectation),
              IsOk());
  EXPECT_EQ(aead_scheme, AeadScheme::AES256_GCM_SIV);
}

// Verify that the default SealedSecretHeader that binds a secret to MRENCLAVE
// can be parsed from a different enclave with same MRENCLAVE but different
// MRSIGNER.
TEST_F(SgxLocalSecretSealerTest,
       ParseKeyGenerationParamsMrenclaveSuccessDifferentMrsigner) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);

  // Change the current enclave to an enclave with a different MRSIGNER value.
  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_copy_different_mrsigner_);

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &aead_scheme, &sgx_expectation),
              IsOk());
  EXPECT_EQ(aead_scheme, AeadScheme::AES256_GCM_SIV);
}

// Verify that the default SealedSecretHeader that binds a secret to MRENCLAVE
// cannnot be parsed from an enclave with different MRENCLAVE.
TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsMrenclaveFailure) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);

  // Change the current enclave to an enclave with a different MRENCLAVE value.
  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_copy_different_mrenclave_);

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &aead_scheme, &sgx_expectation),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

// Verify that the default SealedSecretHeader that binds a secret to MRSIGNER
// can be parsed from the same enclave.
TEST_F(SgxLocalSecretSealerTest,
       ParseKeyGenerationParamsMrsignerSuccessSameEnclave) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &aead_scheme, &sgx_expectation),
              IsOk());
  EXPECT_EQ(aead_scheme, AeadScheme::AES256_GCM_SIV);
}

// Verify that the default SealedSecretHeader that binds a secret to MRSIGNER
// can be parsed from a different enclave with same MRSIGNER but different
// MRENCLAVE.
TEST_F(SgxLocalSecretSealerTest,
       ParseKeyGenerationParamsMrsignerSuccessDifferentMrenclave) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);

  // Change the current enclave to an enclave with a different MRENCLAVE value.
  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_copy_different_mrenclave_);

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &aead_scheme, &sgx_expectation),
              IsOk());
  EXPECT_EQ(aead_scheme, AeadScheme::AES256_GCM_SIV);
}

// Verify that the default SealedSecretHeader that binds a secret to MRSIGNER
// can be parsed from a different enclave with same MRSIGNER but higher ISVSVN.
TEST_F(SgxLocalSecretSealerTest,
       ParseKeyGenerationParamsMrsignerSuccessHigherSvn) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);

  // Change the current enclave to an enclave with a higher ISVSVN.
  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_copy_higher_isvsvn_);

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &aead_scheme, &sgx_expectation),
              IsOk());
  EXPECT_EQ(aead_scheme, AeadScheme::AES256_GCM_SIV);
}

// Verify that the default SealedSecretHeader that binds a secret to MRSIGNER
// cannnot be parsed from an enclave with different MRSIGNER.
TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsMrsignerFailure) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);

  // Change the current enclave to an enclave with a different MRSIGNER value.
  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_copy_different_mrsigner_);

  AeadScheme aead_scheme;
  SgxIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &aead_scheme, &sgx_expectation),
              StatusIs(absl::StatusCode::kPermissionDenied));
}

// Verify that a secret fails to be sealed with an unsupported AEAD scheme.
TEST_F(SgxLocalSecretSealerTest, SealFailureUnsupportedAeadScheme) {
  CleansingVector<uint8_t> input_secret(kTestSecret,
                                        kTestSecret + kTestSecretSize);
  std::string input_aad(kTestAad);

  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  PrepareSealedSecretHeader(*sealer, &header);
  header.mutable_root_info()->set_aead_scheme(AeadScheme::UNKNOWN_AEAD_SCHEME);

  SealedSecret sealed_secret;
  EXPECT_THAT(sealer->Seal(header, input_aad, input_secret, &sealed_secret),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

// Verify that a secret sealed to MRENCLAVE can be unsealed from the same
// enclave.
TEST_F(SgxLocalSecretSealerTest, SealUnsealMrenclaveSuccessSameEnclave) {
  CleansingVector<uint8_t> input_secret(kTestSecret,
                                        kTestSecret + kTestSecretSize);
  std::string input_aad(kTestAad);

  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  PrepareSealedSecretHeader(*sealer, &header);

  SealedSecret sealed_secret;
  ASSERT_THAT(sealer->Seal(header, input_aad, input_secret, &sealed_secret),
              IsOk());

  std::unique_ptr<SgxLocalSecretSealer> sealer2 =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  CleansingVector<uint8_t> output_secret;
  ASSERT_THAT(sealer2->Unseal(sealed_secret, &output_secret), IsOk());

  EXPECT_EQ(input_secret, output_secret);
}

// Verify that a secret sealed to MRENCLAVE cannot be unsealed from an enclave
// with a different MRENCLAVE value.
TEST_F(SgxLocalSecretSealerTest, SealUnsealMrenclaveFailureDifferentMrenclave) {
  CleansingVector<uint8_t> input_secret(kTestSecret,
                                        kTestSecret + kTestSecretSize);
  std::string input_aad(kTestAad);

  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  PrepareSealedSecretHeader(*sealer, &header);

  SealedSecret sealed_secret;
  ASSERT_THAT(sealer->Seal(header, input_aad, input_secret, &sealed_secret),
              IsOk());

  // Change the current enclave to an enclave with a different MRENCLAVE value.
  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_copy_different_mrenclave_);

  std::unique_ptr<SgxLocalSecretSealer> sealer2 =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  CleansingVector<uint8_t> output_secret;
  EXPECT_THAT(sealer2->Unseal(sealed_secret, &output_secret), Not(IsOk()));
}

// Verify that a secret sealed to MRSIGNER can be unsealed from the same
// enclave.
TEST_F(SgxLocalSecretSealerTest, SealUnsealMrsignerSuccessSameEnclave) {
  CleansingVector<uint8_t> input_secret(kTestSecret,
                                        kTestSecret + kTestSecretSize);
  std::string input_aad(kTestAad);

  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  PrepareSealedSecretHeader(*sealer, &header);

  SealedSecret sealed_secret;
  ASSERT_THAT(sealer->Seal(header, input_aad, input_secret, &sealed_secret),
              IsOk());

  std::unique_ptr<SgxLocalSecretSealer> sealer2 =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  CleansingVector<uint8_t> output_secret;
  ASSERT_THAT(sealer2->Unseal(sealed_secret, &output_secret), IsOk());

  EXPECT_EQ(input_secret, output_secret);
}

// Verify that a secret sealed to MRSIGNER can be unsealed from different
// enclave with the same MRSIGNER value but a different MRENCLAVE value.
TEST_F(SgxLocalSecretSealerTest, SealUnsealMrsignerSuccessSameMrsigner) {
  CleansingVector<uint8_t> input_secret(kTestSecret,
                                        kTestSecret + kTestSecretSize);
  std::string input_aad(kTestAad);

  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  PrepareSealedSecretHeader(*sealer, &header);

  SealedSecret sealed_secret;
  ASSERT_THAT(sealer->Seal(header, input_aad, input_secret, &sealed_secret),
              IsOk());

  // Change the current enclave to an enclave with a different MRENCLAVE value
  // but the same MRSIGNER value.
  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_copy_different_mrenclave_);

  std::unique_ptr<SgxLocalSecretSealer> sealer2 =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  CleansingVector<uint8_t> output_secret;
  ASSERT_THAT(sealer2->Unseal(sealed_secret, &output_secret), IsOk());

  EXPECT_EQ(input_secret, output_secret);
}

// Verify that a secret sealed to MRSIGNER can be unsealed from different
// enclave with the same MRSIGNER value but a higher ISVSVN value.
TEST_F(SgxLocalSecretSealerTest,
       SealUnsealMrsignerSuccessSameMrsignerHigherSvn) {
  CleansingVector<uint8_t> input_secret(kTestSecret,
                                        kTestSecret + kTestSecretSize);
  std::string input_aad(kTestAad);

  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  PrepareSealedSecretHeader(*sealer, &header);

  SealedSecret sealed_secret;
  ASSERT_THAT(sealer->Seal(header, input_aad, input_secret, &sealed_secret),
              IsOk());

  // Change the current enclave to an enclave with a higher ISVSVN value
  // but the same MRSIGNER value.
  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_copy_higher_isvsvn_);

  std::unique_ptr<SgxLocalSecretSealer> sealer2 =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  CleansingVector<uint8_t> output_secret;
  ASSERT_THAT(sealer2->Unseal(sealed_secret, &output_secret), IsOk());

  EXPECT_EQ(input_secret, output_secret);
}

// Verify that a secret sealed to MRSIGNER cannot be unsealed from an enclave
// with a different MRSIGNER value.
TEST_F(SgxLocalSecretSealerTest, SealUnsealMrsignerFailureDifferentMrsigner) {
  CleansingVector<uint8_t> input_secret(kTestSecret,
                                        kTestSecret + kTestSecretSize);
  std::string input_aad(kTestAad);

  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  PrepareSealedSecretHeader(*sealer, &header);

  SealedSecret sealed_secret;
  ASSERT_THAT(sealer->Seal(header, input_aad, input_secret, &sealed_secret),
              IsOk());

  // Change the current enclave to an enclave with a different MRSIGNER value.
  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_copy_different_mrsigner_);

  std::unique_ptr<SgxLocalSecretSealer> sealer2 =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  CleansingVector<uint8_t> output_secret;
  ASSERT_THAT(sealer2->Unseal(sealed_secret, &output_secret), Not(IsOk()));
}

// Verify that a secret sealed to MRSIGNER cannot be unsealed from different
// enclave with the same MRSIGNER value but a lower ISVSVN value.
TEST_F(SgxLocalSecretSealerTest,
       SealUnsealMrsignerFailureSameMrsignerLowerSvn) {
  CleansingVector<uint8_t> input_secret(kTestSecret,
                                        kTestSecret + kTestSecretSize);
  std::string input_aad(kTestAad);

  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_copy_higher_isvsvn_);

  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  PrepareSealedSecretHeader(*sealer, &header);

  SealedSecret sealed_secret;
  ASSERT_THAT(sealer->Seal(header, input_aad, input_secret, &sealed_secret),
              IsOk());

  // Change the current enclave to an enclave with a lower ISVSVN value
  // but the same MRSIGNER value.
  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_);

  std::unique_ptr<SgxLocalSecretSealer> sealer2 =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  CleansingVector<uint8_t> output_secret;
  EXPECT_THAT(sealer2->Unseal(sealed_secret, &output_secret), Not(IsOk()));
}

// Verify that a secret cannot be unsealed by an enclave whose identity differs
// in any of the valid, non-required ATTRIBUTES bits that are considered
// relevant to the ACL.
TEST_F(SgxLocalSecretSealerTest, SealUnsealFailureAttributesMismatch) {
  CleansingVector<uint8_t> input_secret(kTestSecret,
                                        kTestSecret + kTestSecretSize);
  std::string input_aad(kTestAad);

  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  PrepareSealedSecretHeader(*sealer, &header);

  SealedSecret sealed_secret;
  ASSERT_THAT(sealer->Seal(header, input_aad, input_secret, &sealed_secret),
              IsOk());

  SgxIdentityExpectation expectation;
  ASSERT_THAT(
      sgx::ParseSgxExpectation(header.client_acl().expectation(), &expectation),
      IsOk());
  sgx::SecsAttributeSet match_spec_attributes(expectation.match_spec()
                                                  .code_identity_match_spec()
                                                  .attributes_match_mask());

  sgx::SecsAttributeSet required_attributes =
      enclave_->get_required_attributes();
  sgx::SecsAttributeSet all_valid_attributes = enclave_->get_valid_attributes();

  // The set of ATTRIBUTES bits that can conceivably vary and are expected to
  // affect whether an enclave can unseal the secret includes the set of
  // ATTRIBUTES bits that are set in the secret ACL, are considered valid, and
  // are not required to be set.
  sgx::SecsAttributeSet can_vary_attributes =
      ((match_spec_attributes & all_valid_attributes) & ~required_attributes);

  // The actual set of ATTRIBUTES in the sealer's identity.
  sgx::SecsAttributeSet sealer_attributes(
      expectation.reference_identity().code_identity().attributes());

  // An enclave whose identity only varies in one of the |can_vary_attributes|
  // bits should *not* be able to unseal the secret.
  sgx::FakeEnclave enclave_with_mismatched_attributes(*enclave_);
  for (sgx::AttributeBit bit : sgx::kAllAttributeBits) {
    if (!can_vary_attributes.IsSet(bit)) {
      continue;
    }

    // Create an set of ATTRIBUTES identical to the sealer's, but with |bit|
    // flipped.
    sgx::SecsAttributeSet bit_set;
    ASYLO_ASSERT_OK_AND_ASSIGN(bit_set, sgx::SecsAttributeSet::FromBits({bit}));
    enclave_with_mismatched_attributes.set_attributes(sealer_attributes ^
                                                      bit_set);

    sgx::FakeEnclave::ExitEnclave();
    sgx::FakeEnclave::EnterEnclave(enclave_with_mismatched_attributes);

    std::unique_ptr<SgxLocalSecretSealer> sealer2 =
        SgxLocalSecretSealer::CreateMrsignerSecretSealer();

    CleansingVector<uint8_t> output_secret;
    EXPECT_THAT(sealer2->Unseal(sealed_secret, &output_secret), Not(IsOk()))
        << "Sealer Identity: " << sgx::FormatProto(enclave_->GetIdentity())
        << "Unsealer Identity: "
        << sgx::FormatProto(enclave_with_mismatched_attributes.GetIdentity());
  }
}

// Verify that a secret can be unsealed by an enclave whose identity differs
// only in the valid, non-required ATTRIBUTES bits that are not considered
// relevant to the ACL.
TEST_F(SgxLocalSecretSealerTest,
       SealUnsealSuccessMismatchedDoNotCareAttributes) {
  CleansingVector<uint8_t> input_secret(kTestSecret,
                                        kTestSecret + kTestSecretSize);
  std::string input_aad(kTestAad);

  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  PrepareSealedSecretHeader(*sealer, &header);

  SealedSecret sealed_secret;
  ASSERT_THAT(sealer->Seal(header, input_aad, input_secret, &sealed_secret),
              IsOk());

  SgxIdentityExpectation expectation;
  ASSERT_THAT(
      sgx::ParseSgxExpectation(header.client_acl().expectation(), &expectation),
      IsOk());
  sgx::SecsAttributeSet match_spec_attributes(expectation.match_spec()
                                                  .code_identity_match_spec()
                                                  .attributes_match_mask());

  sgx::SecsAttributeSet required_attributes =
      enclave_->get_required_attributes();
  sgx::SecsAttributeSet all_valid_attributes = enclave_->get_valid_attributes();

  // The set of ATTRIBUTES bits that can conceivably vary and are *not* expected
  // to affect whether an enclave can unseal the secret includes the set of
  // ATTRIBUTES bits that are *not* set in the secret ACL, are considered valid,
  // and are not required to always be set.
  sgx::SecsAttributeSet can_vary_attributes =
      ((~match_spec_attributes & all_valid_attributes) & ~required_attributes);

  // The actual set of ATTRIBUTES in the sealer's identity.
  sgx::SecsAttributeSet sealer_attributes(
      expectation.reference_identity().code_identity().attributes());

  // An enclave whose identity only varies in one of the |can_vary_attributes|
  // bits should be able to unseal the secret successfully.
  sgx::FakeEnclave enclave_with_mismatched_attributes(*enclave_);
  for (sgx::AttributeBit bit : sgx::kAllAttributeBits) {
    if (!can_vary_attributes.IsSet(bit)) {
      continue;
    }

    // Create an set of ATTRIBUTES identical to the sealer's, but with |bit|
    // flipped.
    sgx::SecsAttributeSet bit_set;
    ASYLO_ASSERT_OK_AND_ASSIGN(bit_set, sgx::SecsAttributeSet::FromBits({bit}));
    enclave_with_mismatched_attributes.set_attributes(sealer_attributes ^
                                                      bit_set);

    sgx::FakeEnclave::ExitEnclave();
    sgx::FakeEnclave::EnterEnclave(enclave_with_mismatched_attributes);

    std::unique_ptr<SgxLocalSecretSealer> sealer2 =
        SgxLocalSecretSealer::CreateMrsignerSecretSealer();

    CleansingVector<uint8_t> output_secret;
    EXPECT_THAT(sealer2->Unseal(sealed_secret, &output_secret), IsOk())
        << "Sealer Identity: " << sgx::FormatProto(enclave_->GetIdentity())
        << "Unsealer Identity: "
        << sgx::FormatProto(enclave_with_mismatched_attributes.GetIdentity());
  }
}

// Verifies that sealed secrets contained in local-secret-sealer-generated
// golden data can be unsealed correctly.
TEST_F(SgxLocalSecretSealerTest, BackwardCompatibility) {
  const std::string data_path = absl::GetFlag(FLAGS_test_data_path);

  int fd = open(data_path.c_str(), O_RDONLY);
  ASSERT_GT(fd, 0);
  google::protobuf::io::FileInputStream stream(fd);
  stream.SetCloseOnDelete(true);

  sgx::LocalSecretSealerTestData test_data;
  ASSERT_TRUE(google::protobuf::TextFormat::Parse(&stream, &test_data));

  for (const auto &record : test_data.records()) {
    ASSERT_EQ(record.header().enclave_type(),
              sgx::TestDataRecordHeader::FAKE_ENCLAVE);

    sgx::FakeEnclave enclave;
    enclave.SetIdentity(record.header().sgx_identity());
    sgx::FakeEnclave::ExitEnclave();
    sgx::FakeEnclave::EnterEnclave(enclave);

    // Any SgxLocalSecretSealer, irrespective of the factory with which it was
    // created, is capable of unsealing secrets sealed by other sealers. As
    // such, it is sufficient to test the compatibility of the Unseal()
    // operation using a single configuration of the secret sealer (i.e.,
    // an MRENCLAVE secret sealer).
    std::unique_ptr<SgxLocalSecretSealer> sealer =
        SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
    CleansingVector<uint8_t> plaintext;
    ASSERT_THAT(sealer->Unseal(record.sealed_secret(), &plaintext), IsOk());
    EXPECT_EQ(ByteContainerView(plaintext),
              ByteContainerView(record.plaintext()));
  }
}

}  // namespace
}  // namespace asylo
