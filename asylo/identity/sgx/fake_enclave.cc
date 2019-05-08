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

#include "asylo/identity/sgx/fake_enclave.h"

#include <openssl/cmac.h>
#include <openssl/rand.h>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/util/logging.h"
#include "asylo/identity/sgx/secs_attributes.h"
#include "asylo/identity/util/sha256_hash.pb.h"
#include "asylo/platform/primitives/sgx/sgx_error_space.h"

namespace asylo {
namespace sgx {

FakeEnclave *FakeEnclave::current_ = nullptr;

FakeEnclave::FakeEnclave() {
  mrenclave_.fill(0);
  mrsigner_.fill(0);
  isvprodid_ = 0;
  isvsvn_ = 0;
  ClearSecsAttributeSet(&attributes_);
  miscselect_ = 0;
  cpusvn_.fill(0);
  report_keyid_.fill(0);
  ownerepoch_.fill(0);
  root_key_.fill(0);
  seal_fuses_.fill(0);
}

FakeEnclave *FakeEnclave::GetCurrentEnclave() { return current_; }

void FakeEnclave::EnterEnclave(const FakeEnclave &enclave) {
  if (current_) {
    // The SGX architecture throws an exception if EENTER is invoked from
    // inside an enclave. This behavior is simulated here via the
    // LOG(FATAL) macro.
    LOG(FATAL) << "Already inside an enclave.";
  }
  current_ = new FakeEnclave(enclave);
}

void FakeEnclave::ExitEnclave() {
  if (!current_) {
    // The SGX architecture throws an exception if EEXIT is invoked from
    // outside an enclave. This behavior is simulated here via the
    // LOG(FATAL) macro.
    LOG(FATAL) << "Not inside an enclave.";
  }
  delete current_;
  current_ = nullptr;
}

void FakeEnclave::SetRandomIdentity() {
  mrenclave_ = TrivialRandomObject<decltype(mrenclave_)>();
  mrsigner_ = TrivialRandomObject<decltype(mrsigner_)>();
  isvprodid_ = TrivialRandomObject<uint16_t>();
  isvsvn_ = TrivialRandomObject<uint16_t>();

  // Set attributes_ field to a legal random value.
  GetAllSecsAttributes(&attributes_);
  attributes_ = attributes_ & TrivialRandomObject<SecsAttributeSet>();
  SecsAttributeSet must_be_set_attributes;
  GetMustBeSetSecsAttributes(&must_be_set_attributes);
  attributes_ = attributes_ | must_be_set_attributes;
  // All bits of MISCSELECT, except for bit 0, must be zero.
  miscselect_ = TrivialRandomObject<uint32_t>() & 0x1;
}

void FakeEnclave::SetIdentity(const CodeIdentity &identity) {
  mrenclave_.assign(identity.mrenclave().hash());
  mrsigner_.assign(identity.signer_assigned_identity().mrsigner().hash());
  isvprodid_ = identity.signer_assigned_identity().isvprodid();
  isvsvn_ = identity.signer_assigned_identity().isvsvn();

  if (!ConvertSecsAttributeRepresentation(identity.attributes(),
                                          &attributes_)) {
    LOG(FATAL) << "Error while reading attributes from identity.";
  }
  miscselect_ = identity.miscselect();
}

Status FakeEnclave::GetHardwareRand64(uint64_t *value) {
  RAND_bytes(reinterpret_cast<uint8_t *>(value), sizeof(*value));
  return Status::OkStatus();
}

Status FakeEnclave::DeriveKey(const KeyDependencies &dependencies,
                              HardwareKey *key) {
  static_assert(HardwareKey::size() == AES_BLOCK_SIZE,
                "Mismatch between kHardwareKeySize and AES_BLOCK_SIZE");

  if (AES_CMAC(key->data(), root_key_.data(), root_key_.size(),
               reinterpret_cast<const uint8_t *>(&dependencies),
               sizeof(dependencies)) != 1) {
    // Clear-out any leftover state from the output.
    key->Cleanse();
    return Status(SGX_ERROR_UNEXPECTED, BsslLastErrorString());
  }
  return Status::OkStatus();
}

bool FakeEnclave::operator==(const FakeEnclave &rhs) const {
  return (mrenclave_ == rhs.mrenclave_ && mrsigner_ == rhs.mrsigner_ &&
          isvprodid_ == rhs.isvprodid_ && isvsvn_ == rhs.isvsvn_ &&
          attributes_ == rhs.attributes_ && miscselect_ == rhs.miscselect_ &&
          cpusvn_ == rhs.cpusvn_ && report_keyid_ == rhs.report_keyid_ &&
          ownerepoch_ == rhs.ownerepoch_ && root_key_ == rhs.root_key_ &&
          seal_fuses_ == rhs.seal_fuses_);
}

bool FakeEnclave::operator!=(const FakeEnclave &rhs) const {
  return !(*this == rhs);
}

Status FakeEnclave::GetHardwareKey(const Keyrequest &request,
                                   HardwareKey *key) {
  // Check the alignment of the input parameters. If the parameters are
  // not correctly aligned, SGX hardware throws a #GP(0) exception.
  // Here, this behavior is simulated by invoking the LOG(FATAL) macro.
  if (!AlignedKeyrequestPtr::IsAligned(&request) ||
      !AlignedHardwareKeyPtr::IsAligned(key)) {
    LOG(FATAL) << "Input parameters are not correctly aligned.";
  }

  // Make sure that the KEYREQUEST struct is valid. The KEYREQUEST struct is
  // invalid if any of its reserved bits are set or if the embedded KEYPOLICY
  // field is invalid. In such a situation, the SGX hardware throws a #GP(0)
  // exception. Here, this behavior is simulated by invoking the LOG(FATAL)
  // macro.
  if (request.reserved1 != TrivialZeroObject<decltype(request.reserved1)>() ||
      request.reserved2 != TrivialZeroObject<decltype(request.reserved2)>()) {
    LOG(FATAL) << "Reserved fields/bits in input parameters are not zeroed.";
  }

  // The KEYPOLICY field is invalid if any of its reserved bits are set or if
  // any of its KSS-related bits are set when the enclave's KSS SECS attribute
  // bit is not set.
  if ((request.keypolicy & kKeypolicyReservedBits) != 0 ||
      (!TestAttribute(SecsAttributeBit::KSS, attributes_) &&
       (request.keypolicy & kKeypolicyKssBits) != 0)) {
    LOG(FATAL) << "Input parameter KEYPOLICY is not valid.";
  }

  // Populate a KEYDEPENDENCIES structure based on the KEYREQUEST. This
  // code is pretty much directly taken from the Intel SDM. However only
  // two of the five SGX keys are currently supported. Support for additional
  // keys will be added if and when needed.
  KeyDependencies dependencies;
  switch (request.keyname) {
    case KeyrequestKeyname::SEAL_KEY:
      // Intel does not specify how they compare two CPUSVNs with each
      // other. Consequently, we just check CPUSVNs for equality. This is
      // clearly incorrect, as Intel has indicated that they have partial
      // ordering between CPUSVNs.
      //
      if (request.cpusvn != cpusvn_) {
        return Status(SGX_ERROR_INVALID_CPUSVN,
                      "Access to seal key denied due to incorrect CPUSVN.");
      }
      if (request.isvsvn > isvsvn_) {
        return Status(SGX_ERROR_INVALID_ISVSVN,
                      "ISVSVN value in KEYREQUEST is too large.");
      }
      dependencies.keyname = KeyrequestKeyname::SEAL_KEY;
      dependencies.isvprodid = isvprodid_;
      dependencies.isvsvn = request.isvsvn;
      dependencies.ownerepoch = ownerepoch_;
      dependencies.attributes =
          ((kRequiredSealingAttributesMask | request.attributemask) &
           attributes_);
      dependencies.attributemask = request.attributemask;
      if (request.keypolicy & kKeypolicyMrenclaveBitMask) {
        dependencies.mrenclave = mrenclave_;
      } else {
        dependencies.mrenclave.fill(0);
      }
      if (request.keypolicy & kKeypolicyMrsignerBitMask) {
        dependencies.mrsigner = mrsigner_;
      } else {
        dependencies.mrsigner.fill(0);
      }
      dependencies.keyid = request.keyid;
      dependencies.seal_key_fuses = seal_fuses_;
      dependencies.cpusvn = request.cpusvn;
      dependencies.miscselect = (miscselect_ & request.miscmask);
      dependencies.miscmask = request.miscmask;
      break;

    case KeyrequestKeyname::REPORT_KEY:
      dependencies.keyname = KeyrequestKeyname::REPORT_KEY;
      dependencies.isvprodid = 0;
      dependencies.isvsvn = 0;
      dependencies.ownerepoch = ownerepoch_;
      dependencies.attributes = attributes_;
      ClearSecsAttributeSet(&dependencies.attributemask);
      dependencies.mrenclave = mrenclave_;
      dependencies.mrsigner.fill(0);
      dependencies.keyid = request.keyid;
      dependencies.seal_key_fuses = seal_fuses_;
      dependencies.cpusvn = cpusvn_;
      dependencies.miscselect = miscselect_;
      dependencies.miscmask = 0;
      break;

    default:
      return Status(
          SGX_ERROR_INVALID_KEYNAME,
          absl::StrCat("Key name ", static_cast<uint64_t>(request.keyname),
                       " is not supported"));
  }
  return DeriveKey(dependencies, key);
}

Status FakeEnclave::GetHardwareReport(const Targetinfo &tinfo,
                                      const Reportdata &reportdata,
                                      Report *report) {
  // The SGX EREPORT instruction throws the #GP(0) exception if the parameters
  // are not correctly aligned. This behavior is simulated here by means of a
  // LOG(FATAL) macro.
  if (!AlignedTargetinfoPtr::IsAligned(&tinfo) ||
      !AlignedReportdataPtr::IsAligned(&reportdata) ||
      !AlignedReportPtr::IsAligned(report)) {
    LOG(FATAL) << "Parameters are not correctly aligned";
  }

  // Make sure that the reserved fields/bits in TARGETINFO
  // are set to zero. The Intel SDM is not clear on the hardware behavior
  // if these fields are not zero. Lacking sufficient information,
  // this function invokes LOG(FATAL) to match the behavior of the
  // GetHardwareKey() function in such a scenario.
  SecsAttributeSet all_attributes;
  GetAllSecsAttributes(&all_attributes);
  SecsAttributeSet reserved_attributes = ~all_attributes;
  // All bits other than bit 0 of misc select are reserved.
  uint32_t misc_select_reserved_bits = ~0x1;
  if (tinfo.reserved1 != TrivialZeroObject<decltype(tinfo.reserved1)>() ||
      tinfo.reserved2 != TrivialZeroObject<decltype(tinfo.reserved2)>() ||
      (tinfo.miscselect & misc_select_reserved_bits) != 0 ||
      (tinfo.attributes & reserved_attributes) !=
          TrivialZeroObject<SecsAttributeSet>()) {
    LOG(FATAL) << "Reserved fields/bits in input parameters are not zeroed.";
  }

  report->cpusvn = cpusvn_;
  report->miscselect = miscselect_;
  report->reserved1.fill(0);
  report->attributes = attributes_;
  report->mrenclave = mrenclave_;
  report->reserved2.fill(0);
  report->mrsigner = mrsigner_;
  report->reserved3.fill(0);
  report->isvprodid = isvprodid_;
  report->isvsvn = isvsvn_;
  report->reserved4.fill(0);
  report->reportdata = reportdata;
  report->keyid = report_keyid_;

  // Prepare a KeyDependencies struct to generate the appropriate report key.
  // This code is pretty much directly taken from the EREPORT instruction
  // description in the Intel SDM.
  KeyDependencies dependencies;

  dependencies.keyname = KeyrequestKeyname::REPORT_KEY;
  dependencies.isvprodid = 0;
  dependencies.isvsvn = 0;
  dependencies.ownerepoch = ownerepoch_;
  dependencies.attributes = tinfo.attributes;
  ClearSecsAttributeSet(&dependencies.attributemask);
  dependencies.mrenclave = tinfo.measurement;
  dependencies.mrsigner.fill(0);
  dependencies.keyid = report_keyid_;
  dependencies.seal_key_fuses = seal_fuses_;
  dependencies.cpusvn = cpusvn_;
  dependencies.miscselect = tinfo.miscselect;
  dependencies.miscmask = 0;

  SafeBytes<kHardwareKeySize> report_key;
  ASYLO_RETURN_IF_ERROR(DeriveKey(dependencies, &report_key));

  // Compute the report MAC. SGX uses CMAC to MAC the contents of the report.
  // The last two fields (KEYID and MAC) from the REPORT struct are not
  // included in the MAC computation.
  if (report->mac.size() != AES_BLOCK_SIZE) {
    return Status(
        SGX_ERROR_INVALID_PARAMETER,
        "Size of the mac field in the REPORT structure is incorrect.");
  }

  if (AES_CMAC(report->mac.data(), report_key.data(), report_key.size(),
               reinterpret_cast<uint8_t *>(report),
               offsetof(Report, keyid)) != 1) {
    // Clear-out any leftover state from the output.
    report->mac.Cleanse();
    return Status(SGX_ERROR_UNEXPECTED, BsslLastErrorString());
  }
  return Status::OkStatus();
}

}  // namespace sgx
}  // namespace asylo
