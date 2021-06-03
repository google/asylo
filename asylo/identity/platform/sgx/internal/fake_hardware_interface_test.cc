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

#include <openssl/aes.h>
#include <openssl/cmac.h>

#include <limits>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/internal/fake_enclave.h"
#include "asylo/identity/platform/sgx/internal/hardware_interface.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/identity/platform/sgx/internal/self_identity.h"
#include "asylo/identity/platform/sgx/miscselect_util.h"
#include "asylo/platform/primitives/sgx/sgx_error_matchers.h"
#include "asylo/test/util/proto_matchers.h"
#include "asylo/test/util/status_matchers.h"

// This file implements some basic, sanity-checking tests for the
// fake-hardware-interface implementation. It does not test the fake
// implementation very rigorously.
namespace asylo {
namespace sgx {
namespace {

using ::testing::Not;

using Measurement = UnsafeBytes<kSha256DigestLength>;
using Keyid = UnsafeBytes<kReportKeyidSize>;

template <class T1, class T2>
std::string HexDumpObjectPair(const char *obj1_name, T1 obj1,
                              const char *obj2_name, T2 obj2) {
  return absl::StrCat(obj1_name, ":\n", ConvertTrivialObjectToHexString(obj1),
                      "\n", obj2_name, ":\n",
                      ConvertTrivialObjectToHexString(obj2), "\n");
}

void FlipLowFourBits(uint8_t *data) {
  *data ^= TrivialRandomObject<uint8_t>() & static_cast<uint8_t>(0xF);
}

uint16_t GenerateRandomKeypolicy(const SecsAttributeSet &attributes) {
  uint16_t keypolicy_valid_bits =
      kKeypolicyMrenclaveBitMask | kKeypolicyMrsignerBitMask;
  if (attributes.IsSet(AttributeBit::KSS)) {
    keypolicy_valid_bits |= kKeypolicyKssBits;
  }
  return TrivialRandomObject<uint16_t>() & keypolicy_valid_bits;
}

// Tests that key-derivation for the key specified in |request| varies
// appropriately with MRENCLAVE. |request| must be aligned according to SGX
// architecture requirements.
void TestKeyDerivationChangesWithMrenclave(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  StatusOr<HardwareKey> key1, key2;

  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();
  for (int i = 0; i < 1000; i++) {
    request->keypolicy = GenerateRandomKeypolicy(enclave->get_attributes());
    key1 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key1) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // Set MRENCLAVE to a new random value. The probability that this will match
    // the old value is 2^-256.
    enclave->set_mrenclave(TrivialRandomObject<Measurement>());
    key2 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key2) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // The new MRENCLAVE value is extremely unlikely to match the old value, so
    // expect the key to change if and only if the MRSIGNER KEYPOLICY bit is
    // set.
    bool expect_key_change =
        (request->keypolicy & kKeypolicyMrenclaveBitMask) != 0;
    EXPECT_EQ(key1.value() != key2.value(), expect_key_change)
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
}

// Tests that key-derivation for the key specified in |request| varies
// appropriately with MRSIGNER. |request| must be aligned according to SGX
// architecture requirements.
void TestKeyDerivationChangesWithMrsigner(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  StatusOr<HardwareKey> key1, key2;

  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();
  for (int i = 0; i < 1000; i++) {
    request->keypolicy = GenerateRandomKeypolicy(enclave->get_attributes());
    key1 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key1) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // Set MRSIGNER to a new random value. The probability that this will match
    // the old value is 2^-256.
    enclave->set_mrsigner(TrivialRandomObject<Measurement>());
    key2 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key2) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // The new MRSIGNER value is extremely unlikely to match the old value, so
    // expect the seal key to change if and only if the MRSIGNER KEYPOLICY bit
    // is set.
    bool expect_key_change =
        (request->keypolicy & kKeypolicyMrsignerBitMask) != 0;
    EXPECT_EQ(key1.value() != key2.value(), expect_key_change)
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
}

// Tests that key-derivation for the key specified in |request| varies
// appropriately with ISVPRODID. |request| must be aligned according to SGX
// architecture requirements.
void TestKeyDerivationChangesWithIsvprodid(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  StatusOr<HardwareKey> key1, key2;

  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();
  for (int i = 0; i < 1000; i++) {
    request->keypolicy = GenerateRandomKeypolicy(enclave->get_attributes());
    key1 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key1) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // Set ISVPRODID to a new random value. The probability that this will match
    // the old value is 1/16.
    uint16_t prev_isvprodid = enclave->get_isvprodid();
    enclave->set_isvprodid(TrivialRandomObject<uint16_t>() & 0x0F);
    key2 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key2) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // A key change is expected if and only if the new ISVPRODID value is
    // different than the old value and the NOISVPRODID KEYPOLICY bit is clear.
    bool expect_key_change =
        (enclave->get_isvprodid() != prev_isvprodid) &&
        ((request->keypolicy & kKeypolicyNoisvprodidBitMask) == 0);
    EXPECT_EQ(key1.value() != key2.value(), expect_key_change)
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
}

// Tests that key-derivation for the key specified in |request| varies
// appropriately with ISVPRODID. |request| must be aligned according to SGX
// architecture requirements.
void TestKeyDerivationChangesWithIsvsvn(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  StatusOr<HardwareKey> key1, key2;

  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();
  request->isvsvn = enclave->get_isvsvn();
  for (int i = 0; i < 1000; i++) {
    request->keypolicy = GenerateRandomKeypolicy(enclave->get_attributes());
    key1 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key1) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // Set ISVSVN to a new random value. The probability that this will match
    // the old value is 1/16.
    uint16_t prev_isvsvn = enclave->get_isvsvn();
    uint16_t isvsvn = TrivialRandomObject<uint16_t>() & 0x0F;
    enclave->set_isvsvn(isvsvn);
    request->isvsvn = isvsvn;
    key2 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key2) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // A key change is expected if and only if the new ISVSVN value is different
    // than the old value.
    bool expect_key_change = (isvsvn != prev_isvsvn);
    EXPECT_EQ(key1.value() != key2.value(), expect_key_change)
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
}

// Tests that key-derivation for the key specified in |request| varies
// appropriately with ATTRIBUTES. |request| must be aligned according to SGX
// architecture requirements.
void TestKeyDerivationChangesWithAttributes(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  StatusOr<HardwareKey> key1, key2;

  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  SecsAttributeSet do_not_care_attributes =
      SecsAttributeSet::GetDefaultDoNotCareBits();

  enclave->set_attributes(TrivialRandomObject<SecsAttributeSet>());
  SecsAttributeSet next = enclave->get_attributes();
  for (int i = 0; i < 1000; i++) {
    key1 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key1) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // Modify SECS attributes randomly. There are 15 attributes defined.
    // Of these, 3 attributes are defined by the architecture as must-be-one,
    // and 6 others are do-not-care. Thus, there are only 6 attributes that
    // one cares about that are variable. This makes the probability of
    // new attributes effectively matching the previous attributes equal to
    // 1/64.
    SecsAttributeSet prev = enclave->get_attributes();
    enclave->set_attributes(TrivialRandomObject<SecsAttributeSet>());
    next = enclave->get_attributes();
    key2 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key2) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // A key change is expected if and only if any of attributes selected by the
    // KEYPOLICY mask have changed.
    bool expect_key_change =
        (prev & ~do_not_care_attributes) != (next & ~do_not_care_attributes);
    EXPECT_EQ(key1.value() != key2.value(), expect_key_change)
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
}

// Tests that key-derivation for the key specified in |request| varies
// appropriately with MISCSELECT. |request| must be aligned according to SGX
// architecture requirements.
void TestKeyDerivationChangesWithMiscselect(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  StatusOr<HardwareKey> key1, key2;

  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  // Ensure that only valid bits in MISCSELECT are set.
  enclave->set_miscselect(TrivialRandomObject<uint32_t>() &
                          kValidMiscselectBitmask);
  for (int i = 0; i < 100; i++) {
    key1 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key1) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);
    uint32_t prev = enclave->get_miscselect();
    enclave->set_miscselect(TrivialRandomObject<uint32_t>() &
                            kValidMiscselectBitmask);
    key2 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key2) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // Since the MISCMASK is set to all 1s, a key change is expected if and only
    // if the new MISCSELECT is different than the old one.
    bool expect_key_change = (prev != enclave->get_miscselect());
    EXPECT_EQ(key1.value() != key2.value(), expect_key_change)
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
}

// Tests that key-derivation for the key specified in |request| varies
// appropriately with ISVFAMILYID. |request| must be aligned according to SGX
// architecture requirements.
void TestKeyDerivationChangesWithIsvfamilyid(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  StatusOr<HardwareKey> key1, key2;

  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  for (int i = 0; i < 1000; i++) {
    request->keypolicy = GenerateRandomKeypolicy(enclave->get_attributes());
    key1 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key1) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // Randomly flip first four bits of ISVFAMILYID. The probability that the
    // new value will match the old value is 1/16.
    UnsafeBytes<kIsvfamilyidSize> prev_isvfamilyid = enclave->get_isvfamilyid();
    UnsafeBytes<kIsvfamilyidSize> isvfamilyid = prev_isvfamilyid;
    FlipLowFourBits(isvfamilyid.data());
    enclave->set_isvfamilyid(isvfamilyid);
    key2 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key2) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // A key change is expected if and only if the new ISVFAMILYID is different
    // than the old one and the ISVFAMILYID bit in KEYPOLICY is set.
    bool expect_key_change =
        (isvfamilyid != prev_isvfamilyid) &&
        ((request->keypolicy & kKeypolicyIsvfamilyidBitMask) != 0);
    EXPECT_EQ(key1.value() != key2.value(), expect_key_change)
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
}

// Tests that key-derivation for the key specified in |request| varies
// appropriately with ISVEXTPRODID. |request| must be aligned according to SGX
// architecture requirements.
void TestKeyDerivationChangesWithIsvextprodid(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  StatusOr<HardwareKey> key1, key2;

  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  for (int i = 0; i < 1000; i++) {
    request->keypolicy = GenerateRandomKeypolicy(enclave->get_attributes());
    key1 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key1) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // Randomly flip first four bits of ISVFAMILYID. The probability that the
    // new value will match the old value is 1/16.
    UnsafeBytes<kIsvextprodidSize> prev_isvextprodid =
        enclave->get_isvextprodid();
    UnsafeBytes<kIsvextprodidSize> isvextprodid = prev_isvextprodid;
    FlipLowFourBits(isvextprodid.data());
    enclave->set_isvextprodid(isvextprodid);
    key2 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key2) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // A key change is expected if and only if the new ISVEXTPRODID is different
    // than the old one and the ISVEXTPRODID bit in KEYPOLICY is set.
    bool expect_key_change =
        (isvextprodid != prev_isvextprodid) &&
        ((request->keypolicy & kKeypolicyIsvextprodidBitMask) != 0);
    EXPECT_EQ(key1.value() != key2.value(), expect_key_change)
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
}

// Tests that key-derivation for the key specified in |request| varies
// appropriately with CONFIGID. |request| must be aligned according to SGX
// architecture requirements.
void TestKeyDerivationChangesWithConfigid(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  StatusOr<HardwareKey> key1, key2;

  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  for (int i = 0; i < 1000; i++) {
    request->keypolicy = GenerateRandomKeypolicy(enclave->get_attributes());
    key1 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key1) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // Randomly flip first four bits of ISV. The probability that the new value
    // will match the old value is 1/16.
    UnsafeBytes<kConfigidSize> prev_configid = enclave->get_configid();
    UnsafeBytes<kConfigidSize> configid = prev_configid;
    FlipLowFourBits(configid.data());
    enclave->set_configid(configid);
    key2 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key2) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // A key change is expected if and only if the new CONFIGID is different
    // than the old one and the CONFIGID bit in KEYPOLICY is set.
    bool expect_key_change =
        (configid != prev_configid) &&
        ((request->keypolicy & kKeypolicyConfigidBitMask) != 0);
    EXPECT_EQ(key1.value() != key2.value(), expect_key_change)
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
}

// Tests that key-derivation for the key specified in |request| varies
// appropriately with CONFIGSVN. |request| must be aligned according to SGX
// architecture requirements.
void TestKeyDerivationChangesWithConfigsvn(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  StatusOr<HardwareKey> key1, key2;

  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  request->configsvn = enclave->get_configsvn();
  for (int i = 0; i < 1000; i++) {
    request->keypolicy = GenerateRandomKeypolicy(enclave->get_attributes());
    key1 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key1) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // Randomly flip low four bits of CONFIGSVN. The probability that the new
    // value will match the old value is 1/16.
    uint16_t prev_configsvn = enclave->get_configsvn();
    uint16_t configsvn = prev_configsvn;
    FlipLowFourBits(reinterpret_cast<uint8_t *>(&configsvn));
    enclave->set_configsvn(configsvn);
    request->configsvn = configsvn;
    key2 = hardware->GetKey(*request);
    ASYLO_ASSERT_OK(key2) << HexDumpObjectPair("Enclave", *enclave,
                                               "Keyrequest", *request);

    // A key change is expected if and only if the new CONFIGSVN is different
    // than the old one and the CONFIGID bit in KEYPOLICY is set.
    bool expect_key_change =
        (configsvn != prev_configsvn) &&
        ((request->keypolicy & kKeypolicyConfigidBitMask) != 0);
    EXPECT_EQ(key1.value() != key2.value(), expect_key_change)
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
}

// Tests that ISVSVN-based access-control works correctly for the key specified
// in |request|. |request| must be aligned according to SGX architecture
// requirements.
void TestKeyIsvsvnAccessControl(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  // Set ISVSVN to a value in [1, MAX - 1].
  while (enclave->get_isvsvn() == 0 ||
         enclave->get_isvsvn() == std::numeric_limits<uint16_t>::max()) {
    enclave->set_isvsvn(TrivialRandomObject<uint16_t>());
  }

  // Request a key corresponding to a lower ISVSVN.
  request->isvsvn = enclave->get_isvsvn() - 1;
  StatusOr<HardwareKey> key = hardware->GetKey(*request);
  ASYLO_EXPECT_OK(key) << HexDumpObjectPair("Enclave", *enclave, "Keyrequest",
                                            *request);

  // Request a key corresponding to a higher ISVSVN.
  request->isvsvn = enclave->get_isvsvn() + 1;
  key = hardware->GetKey(*request);
  EXPECT_THAT(key, SgxErrorIs(SGX_ERROR_INVALID_ISVSVN))
      << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
}

// Tests that CONFIGSVN-based access-control works correctly for the key
// specified in |request|. |request| must be aligned according to SGX
// architecture requirements.
void TestKeyConfigsvnAccessControl(Keyrequest *request) {
  std::unique_ptr<HardwareInterface> hardware =
      HardwareInterface::CreateDefault();
  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  // Set CONFIGSVN to a value in [1, MAX - 1].
  while (enclave->get_configsvn() == 0 ||
         enclave->get_configsvn() == std::numeric_limits<uint16_t>::max()) {
    enclave->set_configsvn(TrivialRandomObject<uint16_t>());
  }

  // Request a key corresponding to a lower CONFIGSVN.
  request->configsvn = enclave->get_configsvn() - 1;
  StatusOr<HardwareKey> key = hardware->GetKey(*request);
  ASYLO_EXPECT_OK(key) << HexDumpObjectPair("Enclave", *enclave, "Keyrequest",
                                            *request);

  // Request a key corresponding to a higher CONFIGSVN.
  request->configsvn = enclave->get_configsvn() + 1;
  key = hardware->GetKey(*request);
  EXPECT_THAT(key, SgxErrorIs(SGX_ERROR_INVALID_ISVSVN))
      << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
}

class FakeEnclaveTest : public ::testing::Test {
 protected:
  FakeEnclaveTest() : hardware_(HardwareInterface::CreateDefault()) {
    // Allow the enclave to set the KSS attribute.
    enclave_.add_valid_attribute(AttributeBit::KSS);

    // Set up a fake enclave. All tests use this enclave either directly,
    // or tweaked copies of it as needed.
    enclave_.SetRandomIdentity();

    // First, set the default seal key request to all zeros.
    *seal_key_request_ = TrivialZeroObject<Keyrequest>();

    // Set up the default seal key request
    seal_key_request_->keyname = KeyrequestKeyname::SEAL_KEY;

    // By default, set keyrequest to care about both, mrenclave and mrsigner.
    seal_key_request_->keypolicy =
        kKeypolicyMrenclaveBitMask | kKeypolicyMrsignerBitMask;

    // Set attributemask to care about all attributes except for those that
    // are on the default "Do Not Care" list.
    seal_key_request_->attributemask =
        ~SecsAttributeSet::GetDefaultDoNotCareBits();

    seal_key_request_->keyid = TrivialRandomObject<Keyid>();

    // Only one bit in miscmask is defined. It is safest to treat all bits
    // as security sensitive.
    seal_key_request_->miscmask = std::numeric_limits<uint32_t>::max();

    // Set up default report key request.
    *report_key_request_ = *seal_key_request_;
    report_key_request_->keyname = KeyrequestKeyname::REPORT_KEY;
  }

  FakeEnclave enclave_;
  std::unique_ptr<HardwareInterface> hardware_;
  AlignedKeyrequestPtr seal_key_request_;
  AlignedKeyrequestPtr report_key_request_;
};

// The following test makes sure that GetCurrentEnclave, EnterEnclave, and
// ExitEnclave work correctly.
TEST_F(FakeEnclaveTest, CurrentEnclave) {
  EXPECT_EQ(FakeEnclave::GetCurrentEnclave(), nullptr);
  FakeEnclave::EnterEnclave(enclave_);

  FakeEnclave *current_enclave = FakeEnclave::GetCurrentEnclave();
  ASSERT_NE(current_enclave, nullptr);

  // Verify that GetCurrentEnclave is idempotent.
  ASSERT_EQ(FakeEnclave::GetCurrentEnclave(), current_enclave);

  // Verify that the enclave returned by the GetCurrentEnclave() method has
  // correct values.
  EXPECT_EQ(*current_enclave, enclave_) << HexDumpObjectPair(
      "LHS FakeEnclave (*current_enclave)", *current_enclave,
      "RHS FakeEnclave (enclave_)", enclave_);

  FakeEnclave::ExitEnclave();
  EXPECT_EQ(FakeEnclave::GetCurrentEnclave(), nullptr);
}

TEST_F(FakeEnclaveTest, SetIdentity) {
  enclave_.remove_valid_attribute(AttributeBit::KSS);
  enclave_.SetRandomIdentity();
  FakeEnclave::EnterEnclave(enclave_);
  SgxIdentity identity = GetSelfIdentity()->sgx_identity;
  FakeEnclave::ExitEnclave();

  FakeEnclave enclave2;
  enclave2.SetIdentity(identity);

  FakeEnclave::EnterEnclave(enclave2);
  SgxIdentity identity2 = GetSelfIdentity()->sgx_identity;

  EXPECT_THAT(identity, EqualsProto(identity2));
  FakeEnclave::ExitEnclave();
}

TEST_F(FakeEnclaveTest, GetIdentity) {
  FakeEnclave enclave1;
  enclave1.remove_valid_attribute(AttributeBit::KSS);
  enclave1.SetRandomIdentity();

  SgxIdentity identity = enclave1.GetIdentity();

  FakeEnclave::EnterEnclave(enclave1);
  EXPECT_THAT(identity, EqualsProto(GetSelfIdentity()->sgx_identity));
  FakeEnclave::ExitEnclave();

  FakeEnclave enclave2;
  enclave2.SetIdentity(identity);

  EXPECT_THAT(enclave2.GetIdentity(), EqualsProto(identity));

  FakeEnclave enclave3;
  enclave3.remove_valid_attribute(AttributeBit::KSS);
  enclave3.SetRandomIdentity();

  // The probability that the two identities are identical is exceedingly
  // unlikely. The probability of MRENCLAVE equality is 2^-256. The probability
  // of MRSIGNER equality is also 2^-256.
  EXPECT_THAT(enclave3.GetIdentity(), Not(EqualsProto(identity)));
}

// Verify that key-generation actually writes something in its output
// parameter (i.e., the output parameter does not stay uniformly zero after
// the function call). This check relies on the fact that the probability of a
// generated key being all zeros is O(2^-128). Again, this is just a smoke
// test.
TEST_F(FakeEnclaveTest, SealKeyGeneratesNonZeroKey) {
  FakeEnclave::EnterEnclave(enclave_);

  HardwareKey key;
  ASYLO_ASSERT_OK_AND_ASSIGN(key, hardware_->GetKey(*seal_key_request_));

  HardwareKey zero_key;
  zero_key.fill(0);
  EXPECT_NE(key, zero_key) << "GetKey returned zero key." << std::endl
                           << HexDumpObjectPair("Enclave", enclave_,
                                                "Keyrequest",
                                                *seal_key_request_);
  FakeEnclave::ExitEnclave();
}

// Verify that changing MRENCLAVE changes the key value if and only if the
// MRENCLAVE bit of key_policy is set, and does not change value when that bit
// is not set.TEST_F(FakeEnclaveTest, SealKeyChangesWithMrenclave) {
TEST_F(FakeEnclaveTest, SealKeyChangesWithMrenclave) {
  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(
      TestKeyDerivationChangesWithMrenclave(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify that changing MRSIGNER changes the key value if and only if the
// MRSIGNER bit of key_policy is set, and does not change value when that bit is
// not set.
TEST_F(FakeEnclaveTest, SealKeyChangesWithMrsigner) {
  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(
      TestKeyDerivationChangesWithMrsigner(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify that changing ISVPRODID changes the key value.
TEST_F(FakeEnclaveTest, SealKeyChangesWithIsvprodid) {
  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(
      TestKeyDerivationChangesWithIsvprodid(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify that changing ISVPRODID changes the key value if and only if the
// NOISVPRODID bit in KEYPOLICY is not set.
TEST_F(FakeEnclaveTest, SealKeyChangesWithIsvsvn) {
  // This test requires that the KSS attribute bit is set. So add this bit to
  // the "required" bits of this enclave, and generate a new random identity.
  enclave_.add_required_attribute(AttributeBit::KSS);
  enclave_.SetRandomIdentity();

  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(
      TestKeyDerivationChangesWithIsvsvn(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify that changing ATTRIBUTES changes the key value when ATTRIBUTESMASK
// selects those bits.
TEST_F(FakeEnclaveTest, SealKeyChangesWithAttributes) {
  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(
      TestKeyDerivationChangesWithAttributes(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify that changing MISCSELECT changes the key value when MISCSELECTMASK
// selects those bits (which is always the case).
TEST_F(FakeEnclaveTest, SealKeyChangesWithMiscselect) {
  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(
      TestKeyDerivationChangesWithMiscselect(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify that changing ISVFAMILYID changes the seal key if and only the
// ISVFAMILYID bit in KEYPOLICY is set.
TEST_F(FakeEnclaveTest, SealKeyChangesWithIsvfamilyid) {
  // This test requires that the KSS attribute bit is set. So add this bit to
  // the "required" bits of this enclave, and generate a new random identity.
  enclave_.add_required_attribute(AttributeBit::KSS);
  enclave_.SetRandomIdentity();

  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(
      TestKeyDerivationChangesWithIsvfamilyid(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify that changing ISVEXTPRODID changes the seal key if and only the
// ISVEXTPRODID bit in KEYPOLICY is set.
TEST_F(FakeEnclaveTest, SealKeyChangesWithIsvextprodid) {
  // This test requires that the KSS attribute bit is set. So add this bit to
  // the "required" bits of this enclave, and generate a new random identity.
  enclave_.add_required_attribute(AttributeBit::KSS);
  enclave_.SetRandomIdentity();

  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(
      TestKeyDerivationChangesWithIsvextprodid(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify that changing CONFIGID changes the seal key if and only the
// CONFIGID bit in KEYPOLICY is set.
TEST_F(FakeEnclaveTest, SealKeyChangesWithConfigid) {
  // This test requires that the KSS attribute bit is set. So add this bit to
  // the "required" bits of this enclave, and generate a new random identity.
  enclave_.add_required_attribute(AttributeBit::KSS);
  enclave_.SetRandomIdentity();

  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(
      TestKeyDerivationChangesWithConfigid(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify that changing CONFIGSVN changes the seal key if and only the
// CONFIGID bit in KEYPOLICY is set.
TEST_F(FakeEnclaveTest, SealKeyChangesWithConfigsvn) {
  // This test requires that the KSS attribute bit is set. So add this bit to
  // the "required" bits of this enclave, and generate a new random identity.
  enclave_.add_required_attribute(AttributeBit::KSS);
  enclave_.SetRandomIdentity();

  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(
      TestKeyDerivationChangesWithConfigsvn(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify that an enclave can access a seal key with a KEYREQUEST.ISVSVN value
// that is lower than its own ISVSVN and cannot access a seal key with
// KEYREQUEST.ISVSVN value that is higher than its own ISVSVN.
TEST_F(FakeEnclaveTest, SealKeyIsvsvnAccessControl) {
  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(TestKeyIsvsvnAccessControl(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify that an enclave can access a seal key with a KEYREQUEST.CONFIGSVN
// value that is lower than its own CONFIGSVN and cannot access a seal key with
// KEYREQUEST.CONFIGSVN value that is higher than its own CONFIGSVN.
TEST_F(FakeEnclaveTest, SealKeyConfigsvnAccessControl) {
  // This test requires that the KSS attribute bit is set. So add this bit to
  // the "required" bits of this enclave, and generate a new random identity.
  enclave_.add_required_attribute(AttributeBit::KSS);
  enclave_.SetRandomIdentity();

  FakeEnclave::EnterEnclave(enclave_);
  ASSERT_NO_FATAL_FAILURE(
      TestKeyConfigsvnAccessControl(seal_key_request_.get()));
  FakeEnclave::ExitEnclave();
}

// Verify the REPORT functionality.
TEST_F(FakeEnclaveTest, Report) {
  FakeEnclave enclave1 = enclave_;
  FakeEnclave enclave2 = enclave_;

  for (int i = 0; i < 100; i++) {
    // Randomly set various identity attributes and report_keyid of enclave1.
    enclave1.SetRandomIdentity();
    enclave1.set_report_keyid(TrivialRandomObject<Keyid>());

    // Randomly set various identity attributes of enclave2.
    enclave2.SetRandomIdentity();

    // Enter enclave1 and get a report targeted at enclave2.
    FakeEnclave::EnterEnclave(enclave1);

    AlignedReportdataPtr reportdata;
    *reportdata = TrivialRandomObject<Reportdata>();

    AlignedTargetinfoPtr tinfo;
    *tinfo = TrivialZeroObject<Targetinfo>();
    tinfo->measurement = enclave2.get_mrenclave();
    tinfo->attributes = enclave2.get_attributes();
    tinfo->miscselect = enclave2.get_miscselect();
    tinfo->configid = enclave2.get_configid();
    tinfo->configsvn = enclave2.get_configsvn();

    Report report;
    ASYLO_ASSERT_OK_AND_ASSIGN(report,
                               hardware_->GetReport(*tinfo, *reportdata));

    // Check that the various fields from the report match the expectation.
    EXPECT_EQ(report.body.cpusvn, enclave1.get_cpusvn());
    EXPECT_EQ(report.body.miscselect, enclave1.get_miscselect());
    EXPECT_EQ(report.body.reserved1,
              TrivialZeroObject<decltype(report.body.reserved1)>());
    EXPECT_EQ(report.body.isvextprodid, enclave1.get_isvextprodid());
    EXPECT_EQ(report.body.attributes, enclave1.get_attributes());
    EXPECT_EQ(report.body.mrenclave, enclave1.get_mrenclave());
    EXPECT_EQ(report.body.reserved2,
              TrivialZeroObject<decltype(report.body.reserved2)>());
    EXPECT_EQ(report.body.mrsigner, enclave1.get_mrsigner());
    EXPECT_EQ(report.body.reserved3,
              TrivialZeroObject<decltype(report.body.reserved3)>());
    EXPECT_EQ(report.body.configid, enclave1.get_configid());
    EXPECT_EQ(report.body.isvprodid, enclave1.get_isvprodid());
    EXPECT_EQ(report.body.isvsvn, enclave1.get_isvsvn());
    EXPECT_EQ(report.body.configsvn, enclave1.get_configsvn());
    EXPECT_EQ(report.body.reserved4,
              TrivialZeroObject<decltype(report.body.reserved4)>());
    EXPECT_EQ(report.body.isvfamilyid, enclave1.get_isvfamilyid());
    EXPECT_EQ(report.body.reportdata.data, reportdata->data);
    EXPECT_EQ(report.keyid, enclave1.get_report_keyid());

    // Exit enclave1.
    FakeEnclave::ExitEnclave();

    // Enter enclave2, get the report key, and verify the
    // report MAC.
    FakeEnclave::EnterEnclave(enclave2);
    AlignedKeyrequestPtr request;
    *request = *report_key_request_;
    request->keyid = report.keyid;

    HardwareKey report_key;
    ASYLO_ASSERT_OK_AND_ASSIGN(report_key, hardware_->GetKey(*request));

    SafeBytes<AES_BLOCK_SIZE> expected_mac;
    EXPECT_TRUE(AES_CMAC(
        expected_mac.data(), report_key.data(), report_key.size(),
        reinterpret_cast<uint8_t *>(&report), offsetof(Report, keyid)));
    EXPECT_EQ(report.mac, expected_mac)
        << HexDumpObjectPair("Enclave 1", enclave1, "Enclave 2", enclave2);

    // Exit enclave2
    FakeEnclave::ExitEnclave();
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
