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

#include "asylo/identity/sgx/sgx_local_secret_sealer.h"

#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/sealed_secret.pb.h"
#include "asylo/identity/sgx/code_identity.pb.h"
#include "asylo/identity/sgx/code_identity_util.h"
#include "asylo/identity/sgx/fake_enclave.h"
#include "asylo/identity/sgx/local_sealed_secret.pb.h"
#include "asylo/identity/sgx/local_secret_sealer_helpers.h"
#include "asylo/identity/sgx/self_identity.h"
#include "asylo/platform/common/singleton.h"
#include "asylo/test/util/status_matchers.h"
#include "asylo/util/status.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace {

using ::testing::Not;

constexpr char kBadRootName[] = "BAD";
constexpr char kBadAdditionalInfo[] = "BAD";
constexpr char kBadCpusvn[] = "BAD";
constexpr char kTestString[] = "test";
constexpr sgx::CipherSuite kBadCipherSuite = sgx::UNKNOWN_CIPHER_SUITE;
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
        TrivialRandomObject<UnsafeBytes<SHA256_DIGEST_LENGTH>>());

    // Construct a fake enclave that differs from enclave_ only in MRSIGNER.
    // A secret sealed to MRSIGNER from enclave_ cannot be unsealed by
    // enclave_copy_different_mrsigner_.
    enclave_copy_different_mrsigner_ =
        absl::make_unique<sgx::FakeEnclave>(*enclave_);
    enclave_copy_different_mrsigner_->set_mrsigner(
        TrivialRandomObject<UnsafeBytes<SHA256_DIGEST_LENGTH>>());

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

// Verify that ParseKeyGenerationParamsFromSealedSecretHeader() fails when the
// root type in the header is incorrect.
TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsBadSealingRootType) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);
  header.mutable_root_info()->set_sealing_root_type(REMOTE);

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that ParseKeyGenerationParamsFromSealedSecretHeader() fails when the
// root name in the header is incorrect.
TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsBadSealingRootName) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);
  header.mutable_root_info()->set_sealing_root_name(kBadRootName);

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that ParseKeyGenerationParamsFromSealedSecretHeader() fails when the
// additional info in the header is malformed.
TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsBadAdditionalInfo) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);
  header.mutable_root_info()->set_additional_info(kBadAdditionalInfo);

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that ParseKeyGenerationParamsFromSealedSecretHeader() fails when the
// CPUSVN (which is a part of additional info) is malformed.
TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsBadCpusvn) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);
  sgx::SealedSecretAdditionalInfo info;
  info.set_cpusvn(kBadCpusvn);
  ASSERT_TRUE(info.SerializeToString(
      header.mutable_root_info()->mutable_additional_info()));

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that ParseKeyGenerationParamsFromSealedSecretHeader() fails when the
// CPUSVN (which is a part of additional info) is malformed.
TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsBadCipherSuite) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);
  sgx::SealedSecretAdditionalInfo info;
  info.set_cipher_suite(kBadCipherSuite);
  ASSERT_TRUE(info.SerializeToString(
      header.mutable_root_info()->mutable_additional_info()));

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that ParseKeyGenerationParamsFromSealedSecretHeader() fails when the
// client acl does not have correct format.
TEST_F(SgxLocalSecretSealerTest, ParseKeyGenerationParamsBadClientAcl) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);

  sgx::CodeIdentityMatchSpec spec;
  ASSERT_THAT(sgx::SetDefaultMatchSpec(&spec), IsOk());
  sgx::CodeIdentityExpectation expectation;
  ASSERT_TRUE(
      sgx::SetExpectation(spec, sgx::GetSelfIdentity()->identity, &expectation)
          .ok());
  ASSERT_TRUE(
      sgx::SerializeSgxExpectation(expectation, header.mutable_client_acl()
                                                    ->mutable_acl_group()
                                                    ->add_predicates()
                                                    ->mutable_expectation())
          .ok());
  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation),
              StatusIs(error::GoogleError::INVALID_ARGUMENT));
}

// Verify that the default SealedSecretHeader that binds a secret to MRENCLAVE
// can be parsed from the same enclave.
TEST_F(SgxLocalSecretSealerTest,
       ParseKeyGenerationParamsMrenclaveSuccessSameEnclave) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_TRUE(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation)
                  .ok());
  EXPECT_EQ(cpusvn, sgx::FakeEnclave::GetCurrentEnclave()->get_cpusvn());
  EXPECT_EQ(cipher_suite, sgx::AES256_GCM_SIV);
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

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_TRUE(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation)
                  .ok());
  EXPECT_EQ(cpusvn, sgx::FakeEnclave::GetCurrentEnclave()->get_cpusvn());
  EXPECT_EQ(cipher_suite, sgx::AES256_GCM_SIV);
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

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation),
              StatusIs(error::GoogleError::PERMISSION_DENIED));
}

// Verify that the default SealedSecretHeader that binds a secret to MRSIGNER
// can be parsed from the same enclave.
TEST_F(SgxLocalSecretSealerTest,
       ParseKeyGenerationParamsMrsignerSuccessSameEnclave) {
  std::unique_ptr<SgxLocalSecretSealer> sealer =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  SealedSecretHeader header;
  sealer->SetDefaultHeader(&header);

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_TRUE(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation)
                  .ok());
  EXPECT_EQ(cpusvn, sgx::FakeEnclave::GetCurrentEnclave()->get_cpusvn());
  EXPECT_EQ(cipher_suite, sgx::AES256_GCM_SIV);
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

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_TRUE(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation)
                  .ok());
  EXPECT_EQ(cpusvn, sgx::FakeEnclave::GetCurrentEnclave()->get_cpusvn());
  EXPECT_EQ(cipher_suite, sgx::AES256_GCM_SIV);
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

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_TRUE(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation)
                  .ok());
  EXPECT_EQ(cpusvn, sgx::FakeEnclave::GetCurrentEnclave()->get_cpusvn());
  EXPECT_EQ(cipher_suite, sgx::AES256_GCM_SIV);
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

  UnsafeBytes<sgx::kCpusvnSize> cpusvn;
  sgx::CipherSuite cipher_suite;
  sgx::CodeIdentityExpectation sgx_expectation;
  EXPECT_THAT(sgx::internal::ParseKeyGenerationParamsFromSealedSecretHeader(
                  header, &cpusvn, &cipher_suite, &sgx_expectation),
              StatusIs(error::GoogleError::PERMISSION_DENIED));
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
  ASSERT_TRUE(
      sealer->Seal(header, input_aad, input_secret, &sealed_secret).ok());

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
  ASSERT_TRUE(
      sealer->Seal(header, input_aad, input_secret, &sealed_secret).ok());

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
  ASSERT_TRUE(
      sealer->Seal(header, input_aad, input_secret, &sealed_secret).ok());

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
  ASSERT_TRUE(
      sealer->Seal(header, input_aad, input_secret, &sealed_secret).ok());

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
  ASSERT_TRUE(
      sealer->Seal(header, input_aad, input_secret, &sealed_secret).ok());

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
  ASSERT_TRUE(
      sealer->Seal(header, input_aad, input_secret, &sealed_secret).ok());

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
  ASSERT_TRUE(
      sealer->Seal(header, input_aad, input_secret, &sealed_secret).ok());

  // Change the current enclave to an enclave with a lower ISVSVN value
  // but the same MRSIGNER value.
  sgx::FakeEnclave::ExitEnclave();
  sgx::FakeEnclave::EnterEnclave(*enclave_);

  std::unique_ptr<SgxLocalSecretSealer> sealer2 =
      SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  CleansingVector<uint8_t> output_secret;
  EXPECT_THAT(sealer2->Unseal(sealed_secret, &output_secret), Not(IsOk()));
}

}  // namespace
}  // namespace asylo
