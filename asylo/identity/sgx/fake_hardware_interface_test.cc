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

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/str_cat.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/identity/sgx/fake_enclave.h"
#include "asylo/identity/sgx/hardware_interface.h"
#include "asylo/identity/sgx/self_identity.h"
#include "asylo/test/util/proto_matchers.h"
#include <openssl/aes.h>
#include <openssl/cmac.h>

// This file implements some basic, sanity-checking tests for the
// fake-hardware-interface implementation. It does not test the fake
// implementation very rigorously.
namespace asylo {
namespace sgx {
namespace {

using Measurement = UnsafeBytes<SHA256_DIGEST_LENGTH>;
using Keyid = UnsafeBytes<kReportKeyidSize>;

template <class T1, class T2>
std::string HexDumpObjectPair(const char *obj1_name, T1 obj1, const char *obj2_name,
                         T2 obj2) {
  return absl::StrCat(obj1_name, ":\n", ConvertTrivialObjectToHexString(obj1),
                      "\n", obj2_name, ":\n",
                      ConvertTrivialObjectToHexString(obj2), "\n");
}

class FakeEnclaveTest : public ::testing::Test {
 protected:
  FakeEnclaveTest() {
    // Set the various SecsAttributeSet values.
    GetAllSecsAttributes(&all_attributes_);
    GetMustBeSetSecsAttributes(&must_be_set_attributes_);
    GetDefaultDoNotCareSecsAttributes(&do_not_care_attributes_);
    always_care_attributes_ = kRequiredSealingAttributesMask;

    // Set up a fake enclave. All tests use this enclave either directly,
    // or tweaked copies of it as needed.
    enclave_.SetRandomIdentity();

    // Set up the default seal key request
    seal_key_request_->keyname = KeyrequestKeyname::SEAL_KEY;
    // By default, set keyrequest to care about both, mrenclave and mrsigner.
    seal_key_request_->keypolicy = 0x3;
    seal_key_request_->isvsvn = 0;
    seal_key_request_->reserved1.fill(0);
    seal_key_request_->cpusvn.fill(0);

    // Set attributemask to care about all attributes except for those that
    // are on the default "Do Not Care" list.
    seal_key_request_->attributemask = ~do_not_care_attributes_;

    seal_key_request_->keyid = TrivialRandomObject<Keyid>();

    // Only one bit in miscmask is defined. It is safest to treat all bits
    // as security sensitive.
    seal_key_request_->miscmask = 0xffffffff;
    seal_key_request_->reserved2.fill(0);

    // Set up default report key request.
    *report_key_request_ = *seal_key_request_;
    report_key_request_->keyname = KeyrequestKeyname::REPORT_KEY;
  }

  FakeEnclave enclave_;
  AlignedKeyrequestPtr seal_key_request_;
  AlignedKeyrequestPtr report_key_request_;
  SecsAttributeSet all_attributes_;
  SecsAttributeSet must_be_set_attributes_;
  SecsAttributeSet do_not_care_attributes_;
  SecsAttributeSet always_care_attributes_;
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

// Verify that the GetHardwareRand64 does not return the same
// value four times in a row. This is just a smoke test to ensure that
// the random-number generator is not utterly broken.
TEST_F(FakeEnclaveTest, GetHardwareRand) {
  uint64_t first_value = 0;
  ASSERT_TRUE(GetHardwareRand64(&first_value));
  int collision_count = 0;
  for (int i = 0; i < 3; i++) {
    uint64_t new_value = 0;
    ASSERT_TRUE(GetHardwareRand64(&new_value));
    if (first_value == new_value) {
      collision_count++;
    }
  }
  EXPECT_NE(collision_count, 3);
}

// Verify that FakeEnclave's identity can be set correctly from a CodeIdentity.
TEST_F(FakeEnclaveTest, SetIdentity) {
  FakeEnclave::EnterEnclave(enclave_);
  CodeIdentity identity = GetSelfIdentity()->identity;

  FakeEnclave enclave2;
  enclave2.SetIdentity(identity);

  FakeEnclave::ExitEnclave();
  FakeEnclave::EnterEnclave(enclave2);
  CodeIdentity identity2 = GetSelfIdentity()->identity;

  EXPECT_THAT(identity, EqualsProto(identity2));
  FakeEnclave::ExitEnclave();
}

// Verify that key-generation actually writes something in its output
// parameter (i.e., the output parameter does not stay uniformly zero after
// the function call). This check relies on the fact that the probability of a
// generated key being all zeros is O(2^-128). Again, this is just a smoke
// test.
TEST_F(FakeEnclaveTest, SealKey1) {
  FakeEnclave::EnterEnclave(enclave_);

  AlignedHardwareKeyPtr key;
  key->fill(0);
  ASSERT_TRUE(GetHardwareKey(*seal_key_request_, key.get()));

  HardwareKey zero_key;
  zero_key.fill(0);
  EXPECT_NE(*key, zero_key)
      << "GetHardwareKey returned zero key." << std::endl
      << HexDumpObjectPair("Enclave", enclave_, "Keyrequest",
                           *seal_key_request_);
  FakeEnclave::ExitEnclave();
}

// Verify that changing MRENCLAVE changes the key value when
// bit 0 of key_policy is set, and does not change value when that bit
// is not set.
TEST_F(FakeEnclaveTest, SealKey2) {
  FakeEnclave::EnterEnclave(enclave_);
  AlignedHardwareKeyPtr key1, key2;
  AlignedKeyrequestPtr request;
  *request = *seal_key_request_;
  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  for (int i = 0; i < 1000; i++) {
    request->keypolicy = TrivialRandomObject<uint16_t>() & 0x3;
    ASSERT_TRUE(GetHardwareKey(*request, key1.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    // Set mrenclave to a new random value. The probability that
    // this will match the old value is 2^-256.
    enclave->set_mrenclave(TrivialRandomObject<Measurement>());
    ASSERT_TRUE(GetHardwareKey(*request, key2.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    EXPECT_EQ((*key1 == *key2), ((request->keypolicy & 0x1) == 0))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
  FakeEnclave::ExitEnclave();
}

// Verify that changing MRSIGNER changes the key value when
// bit 2 of key_policy is set, and does not change value when that bit
// is not set.
TEST_F(FakeEnclaveTest, SealKey3) {
  FakeEnclave::EnterEnclave(enclave_);
  AlignedHardwareKeyPtr key1, key2;
  AlignedKeyrequestPtr request;
  *request = *seal_key_request_;
  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  for (int i = 0; i < 1000; i++) {
    request->keypolicy = TrivialRandomObject<uint16_t>() & 0x3;
    ASSERT_TRUE(GetHardwareKey(*request, key1.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    // Set mrsigner to a new random value. The probability that
    // this will match the old value is 2^-256.
    enclave->set_mrsigner(TrivialRandomObject<Measurement>());
    ASSERT_TRUE(GetHardwareKey(*request, key2.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    EXPECT_EQ((*key1 == *key2), ((request->keypolicy & 0x2) == 0))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
  FakeEnclave::ExitEnclave();
}

// Verify that changing ISVPRODID or ISVSVN changes the key value.
TEST_F(FakeEnclaveTest, SealKey4) {
  FakeEnclave::EnterEnclave(enclave_);
  AlignedHardwareKeyPtr key1, key2;
  AlignedKeyrequestPtr request;
  *request = *seal_key_request_;
  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  for (int i = 0; i < 1000; i++) {
    ASSERT_TRUE(GetHardwareKey(*request, key1.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    // Set ISVPRODID to a new random value. The probability that
    // this will match the old value is 1/16.
    uint16_t prev_isvprodid = enclave->get_isvprodid();
    enclave->set_isvprodid(TrivialRandomObject<uint16_t>() & 0x0F);
    ASSERT_TRUE(GetHardwareKey(*request, key2.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    EXPECT_EQ((*key1 == *key2), (enclave->get_isvprodid() == prev_isvprodid))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }

  request->isvsvn = enclave->get_isvsvn();
  for (int i = 0; i < 1000; i++) {
    ASSERT_TRUE(GetHardwareKey(*request, key1.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    // Set ISVSVN to a new random value. The probability that
    // this will match the old value is 1/16.
    uint16_t prev_isvsvn = enclave->get_isvsvn();
    uint16_t isvsvn = TrivialRandomObject<uint16_t>() & 0x0F;
    enclave->set_isvsvn(isvsvn);
    request->isvsvn = isvsvn;
    ASSERT_TRUE(GetHardwareKey(*request, key2.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    EXPECT_EQ((*key1 == *key2), (isvsvn == prev_isvsvn))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
  FakeEnclave::ExitEnclave();
}

// Verify that changing ATTRIBUTES changes the key value when
// ATTRIBUTESMASK selects those bits.
TEST_F(FakeEnclaveTest, SealKey5) {
  FakeEnclave::EnterEnclave(enclave_);
  AlignedHardwareKeyPtr key1, key2;
  AlignedKeyrequestPtr request;
  *request = *seal_key_request_;
  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  SecsAttributeSet next =
      TrivialRandomObject<SecsAttributeSet>() & all_attributes_;
  next = next | must_be_set_attributes_;
  enclave->set_attributes(next);
  for (int i = 0; i < 1000; i++) {
    ASSERT_TRUE(GetHardwareKey(*request, key1.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    // Modify SECS attributes randomly. There are 14 attributes defined.
    // Of these, 3 attributes are defined by the architecture as must-be-one,
    // and 6 others are do-not-care. Thus, there are only 5 attributes that
    // one cares about that are variable. This makes the probability of
    // new attributes effectively matching the previous attributes equal to
    // 1/32.
    SecsAttributeSet prev = enclave->get_attributes();
    next = TrivialRandomObject<SecsAttributeSet>() & all_attributes_;
    next = next | must_be_set_attributes_;
    enclave->set_attributes(next);
    ASSERT_TRUE(GetHardwareKey(*request, key2.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    bool are_attributes_effectively_unchanged =
        (prev & ~do_not_care_attributes_) == (next & ~do_not_care_attributes_);
    EXPECT_EQ((*key1 == *key2), are_attributes_effectively_unchanged)
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
  FakeEnclave::ExitEnclave();
}

// Verify that changing MISCSELECT changes the key value when
// MISCSELECTMASK selects those bits (which is always the case).
TEST_F(FakeEnclaveTest, SealKey6) {
  FakeEnclave::EnterEnclave(enclave_);
  AlignedHardwareKeyPtr key1, key2;
  AlignedKeyrequestPtr request;
  *request = *seal_key_request_;
  FakeEnclave *enclave = FakeEnclave::GetCurrentEnclave();

  // Only least-significant bit in miscselect can be set.
  enclave->set_miscselect(TrivialRandomObject<uint32_t>() & 0x1);
  for (int i = 0; i < 100; i++) {
    ASSERT_TRUE(GetHardwareKey(*request, key1.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    // Modify SECS attributes randomly. There are 14 attributes defined.
    // Of these, 3 attributes are defined by the architecture as must-be-one,
    // and 6 others are do-not-care. Thus, there are only 5 attributes that
    // one cares about that are variable. This makes the probability of
    // new attributes effectively matching the previous attributes equal to
    // 1/32.
    uint32_t prev = enclave->get_miscselect();
    enclave->set_miscselect(TrivialRandomObject<uint32_t>() & 0x1);
    ASSERT_TRUE(GetHardwareKey(*request, key2.get()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
    EXPECT_EQ((*key1 == *key2), (prev == enclave->get_miscselect()))
        << HexDumpObjectPair("Enclave", *enclave, "Keyrequest", *request);
  }
  FakeEnclave::ExitEnclave();
}

// Verify the REPORT functionality
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
    tinfo->measurement = enclave2.get_mrenclave();
    tinfo->attributes = enclave2.get_attributes();
    tinfo->miscselect = enclave2.get_miscselect();
    tinfo->reserved1.fill(0);
    tinfo->reserved2.fill(0);

    AlignedReportPtr report;
    ASSERT_TRUE(GetHardwareReport(*tinfo, *reportdata, report.get()));

    // Check that the various fields from the report match the expectation.
    EXPECT_EQ(report->cpusvn, enclave1.get_cpusvn());
    EXPECT_EQ(report->miscselect, enclave1.get_miscselect());
    EXPECT_EQ(report->reserved1,
              TrivialZeroObject<decltype(report->reserved1)>());
    EXPECT_EQ(report->attributes, enclave1.get_attributes());
    EXPECT_EQ(report->mrenclave, enclave1.get_mrenclave());
    EXPECT_EQ(report->reserved2,
              TrivialZeroObject<decltype(report->reserved2)>());
    EXPECT_EQ(report->mrsigner, enclave1.get_mrsigner());
    EXPECT_EQ(report->reserved3,
              TrivialZeroObject<decltype(report->reserved3)>());
    EXPECT_EQ(report->isvprodid, enclave1.get_isvprodid());
    EXPECT_EQ(report->isvsvn, enclave1.get_isvsvn());
    EXPECT_EQ(report->reserved4,
              TrivialZeroObject<decltype(report->reserved4)>());
    EXPECT_EQ(report->reportdata.data, reportdata->data);
    EXPECT_EQ(report->keyid, enclave1.get_report_keyid());

    // Exit enclave1.
    FakeEnclave::ExitEnclave();

    // Enter enclave2, get the report key, and verify the
    // report MAC.
    FakeEnclave::EnterEnclave(enclave2);
    AlignedKeyrequestPtr request;
    *request = *report_key_request_;
    request->keyid = report->keyid;
    AlignedHardwareKeyPtr report_key;

    ASSERT_TRUE(GetHardwareKey(*request, report_key.get()));

    SafeBytes<AES_BLOCK_SIZE> expected_mac;
    EXPECT_TRUE(AES_CMAC(
        expected_mac.data(), report_key->data(), report_key->size(),
        reinterpret_cast<uint8_t *>(report.get()), offsetof(Report, keyid)));
    EXPECT_EQ(report->mac, expected_mac)
        << HexDumpObjectPair("Enclave 1", enclave1, "Enclave 2", enclave2);

    // Exit enclave2
    FakeEnclave::ExitEnclave();
  }
}

}  // namespace
}  // namespace sgx
}  // namespace asylo
