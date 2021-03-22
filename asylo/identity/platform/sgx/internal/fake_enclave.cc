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

#include "asylo/identity/platform/sgx/internal/fake_enclave.h"

#include <openssl/cmac.h>
#include <openssl/rand.h>

#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_join.h"
#include "asylo/crypto/sha256_hash.pb.h"
#include "asylo/crypto/util/bssl_util.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/util/logging.h"
#include "asylo/identity/platform/sgx/architecture_bits.h"
#include "asylo/identity/platform/sgx/attributes.pb.h"
#include "asylo/identity/platform/sgx/internal/proto_format.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/platform/primitives/sgx/sgx_errors.h"

namespace asylo {
namespace sgx {
namespace {

constexpr char kHardcodedPkcs15PaddingHex[] =
    "0001"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "003031300D060960864801650304020105000420";

std::string FormatAttributeSet(const SecsAttributeSet &set) {
  return FormatProto(set.ToProtoAttributes());
}

}  // namespace

FakeEnclave *FakeEnclave::current_ = nullptr;

FakeEnclave::FakeEnclave() {
  valid_attributes_ = SecsAttributeSet::GetAllSupportedBits();
  remove_valid_attribute(AttributeBit::KSS);
  required_attributes_ = SecsAttributeSet::GetMustBeSetBits();
  mrenclave_.fill(0);
  mrsigner_.fill(0);
  isvprodid_ = 0;
  isvsvn_ = 0;
  attributes_ = required_attributes_;
  miscselect_ = 0;
  configsvn_ = 0;
  isvextprodid_.fill(0);
  isvfamilyid_.fill(0);
  configid_.fill(0);
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
  mrenclave_ = TrivialRandomObject<UnsafeBytes<kSha256DigestLength>>();
  mrsigner_ = TrivialRandomObject<UnsafeBytes<kSha256DigestLength>>();
  isvprodid_ = TrivialRandomObject<uint16_t>();
  isvsvn_ = TrivialRandomObject<uint16_t>();

  // Set attributes_ field to a legal random value. The set_attributes() method
  // accounts for valid_attributes_ and required_attributes_ constraints.
  set_attributes(TrivialRandomObject<SecsAttributeSet>());

  // All bits of MISCSELECT, except for bit 0, must be zero.
  miscselect_ = TrivialRandomObject<uint32_t>() & kValidMiscselectBitmask;

  // If ATTRIBUTES.KSS is zero, all KSS-related fields must be zero, else they
  // should be set randomly.
  if (!attributes_.IsSet(AttributeBit::KSS)) {
    configsvn_ = 0;
    isvextprodid_.fill(0);
    isvfamilyid_.fill(0);
    configid_.fill(0);
  } else {
    configsvn_ = TrivialRandomObject<uint16_t>();
    isvfamilyid_ = TrivialRandomObject<UnsafeBytes<kIsvfamilyidSize>>();
    isvextprodid_ = TrivialRandomObject<UnsafeBytes<kIsvextprodidSize>>();
    configid_ = TrivialRandomObject<UnsafeBytes<kConfigidSize>>();
  }
}

void FakeEnclave::SetIdentity(const SgxIdentity &sgx_identity) {
  const CodeIdentity &identity = sgx_identity.code_identity();
  const MachineConfiguration &machine_config =
      sgx_identity.machine_configuration();

  if (!SetTrivialObjectFromBinaryString<UnsafeBytes<kSha256DigestLength>>(
           identity.mrenclave().hash(), &mrenclave_)
           .ok()) {
    LOG(FATAL) << "MRENCLAVE from SgxIdentity is invalid: "
               << absl::BytesToHexString(identity.mrenclave().hash());
  }
  if (!SetTrivialObjectFromBinaryString<UnsafeBytes<kSha256DigestLength>>(
           identity.signer_assigned_identity().mrsigner().hash(), &mrsigner_)
           .ok()) {
    LOG(FATAL) << "MRSIGNER from SgxIdentity is invalid: "
               << absl::BytesToHexString(
                      identity.signer_assigned_identity().mrsigner().hash());
  }

  isvprodid_ = identity.signer_assigned_identity().isvprodid();
  isvsvn_ = identity.signer_assigned_identity().isvsvn();

  attributes_ = SecsAttributeSet(identity.attributes());
  if ((attributes_ & valid_attributes_) != attributes_) {
    LOG(FATAL) << "Identity contains illegal attributes. "
               << "Identity Attributes: " << FormatAttributeSet(attributes_)
               << ". Valid Attributes: "
               << FormatAttributeSet(valid_attributes_);
  }
  if ((attributes_ & required_attributes_) != required_attributes_) {
    LOG(FATAL) << "Identity is missing required attributes. "
               << "Identity Attributes: " << FormatAttributeSet(attributes_)
               << ". Required Attributes: "
               << FormatAttributeSet(required_attributes_);
  }
  miscselect_ = identity.miscselect();
  if (!SetTrivialObjectFromBinaryString<UnsafeBytes<kCpusvnSize>>(
           machine_config.cpu_svn().value(), &cpusvn_)
           .ok()) {
    LOG(FATAL) << "CPUSVN from SgxIdentity is invalid: "
               << absl::BytesToHexString(machine_config.cpu_svn().value());
  }
}

SgxIdentity FakeEnclave::GetIdentity() const {
  SgxIdentity sgx_identity;
  CodeIdentity *code_identity = sgx_identity.mutable_code_identity();


  *code_identity->mutable_attributes() = attributes_.ToProtoAttributes();

  code_identity->mutable_mrenclave()->set_hash(
      ConvertTrivialObjectToBinaryString(mrenclave_));

  SignerAssignedIdentity *signer_assigned_identity =
      code_identity->mutable_signer_assigned_identity();
  signer_assigned_identity->mutable_mrsigner()->set_hash(
      ConvertTrivialObjectToBinaryString(mrsigner_));
  signer_assigned_identity->set_isvprodid(isvprodid_);
  signer_assigned_identity->set_isvsvn(isvsvn_);

  code_identity->set_miscselect(miscselect_);

  MachineConfiguration *machine_config =
      sgx_identity.mutable_machine_configuration();
  machine_config->mutable_cpu_svn()->set_value(
      ConvertTrivialObjectToBinaryString(cpusvn_));

  return sgx_identity;
}

bool FakeEnclave::operator==(const FakeEnclave &other) const {
  return (mrenclave_ == other.mrenclave_ && mrsigner_ == other.mrsigner_ &&
          isvprodid_ == other.isvprodid_ && isvsvn_ == other.isvsvn_ &&
          attributes_ == other.attributes_ &&
          miscselect_ == other.miscselect_ && cpusvn_ == other.cpusvn_ &&
          report_keyid_ == other.report_keyid_ &&
          ownerepoch_ == other.ownerepoch_ && root_key_ == other.root_key_ &&
          seal_fuses_ == other.seal_fuses_);
}

bool FakeEnclave::operator!=(const FakeEnclave &other) const {
  return !(*this == other);
}

Status FakeEnclave::GetHardwareKey(const Keyrequest &request,
                                   HardwareKey *key) const {
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
      (!attributes_.IsSet(AttributeBit::KSS) &&
       (request.keypolicy & kKeypolicyKssBits) != 0)) {
    LOG(FATAL) << "Input parameter KEYPOLICY is not valid.";
  }

  // Populate a KEYDEPENDENCIES structure based on the KEYREQUEST. This
  // code is pretty much directly taken from the Intel SDM. However only
  // two of the five SGX keys are currently supported. Support for additional
  // keys will be added if and when needed.
  KeyDependencies key_dependencies;
  KeyDependenciesBase *dependencies = &key_dependencies.dependencies;
  switch (request.keyname) {
    case KeyrequestKeyname::SEAL_KEY:
      // Intel does not specify how they compare two CPUSVNs with each
      // other. Consequently, we just check CPUSVNs for equality. This is
      // clearly incorrect, as Intel has indicated that they have partial
      // ordering between CPUSVNs.
      //
      if (request.cpusvn != cpusvn_) {
        return SgxError(SGX_ERROR_INVALID_CPUSVN,
                        "Access to seal key denied due to incorrect CPUSVN.");
      }
      if (request.isvsvn > isvsvn_) {
        return SgxError(SGX_ERROR_INVALID_ISVSVN,
                        "ISVSVN value in KEYREQUEST is too large.");
      }
      if (request.configsvn > configsvn_) {
        return SgxError(SGX_ERROR_INVALID_ISVSVN,
                        "CONFIGSVN value in KEYREQUEST is too large.");
      }
      dependencies->keyname = KeyrequestKeyname::SEAL_KEY;
      if (request.keypolicy & kKeypolicyIsvfamilyidBitMask) {
        dependencies->isvfamilyid = isvfamilyid_;
      } else {
        dependencies->isvfamilyid.fill(0);
      }
      if (request.keypolicy & kKeypolicyIsvextprodidBitMask) {
        dependencies->isvextprodid = isvextprodid_;
      } else {
        dependencies->isvextprodid.fill(0);
      }
      if (request.keypolicy & kKeypolicyNoisvprodidBitMask) {
        dependencies->isvprodid = 0;
      } else {
        dependencies->isvprodid = isvprodid_;
      }
      dependencies->isvsvn = request.isvsvn;
      dependencies->ownerepoch = ownerepoch_;
      dependencies->attributes =
          ((kRequiredSealingAttributesMask | request.attributemask) &
           attributes_);
      dependencies->attributemask = request.attributemask;
      if (request.keypolicy & kKeypolicyMrenclaveBitMask) {
        dependencies->mrenclave = mrenclave_;
      } else {
        dependencies->mrenclave.fill(0);
      }
      if (request.keypolicy & kKeypolicyMrsignerBitMask) {
        dependencies->mrsigner = mrsigner_;
      } else {
        dependencies->mrsigner.fill(0);
      }
      dependencies->keyid = request.keyid;
      dependencies->seal_key_fuses = seal_fuses_;
      dependencies->cpusvn = request.cpusvn;
      SetTrivialObjectFromHexString(kHardcodedPkcs15PaddingHex,
                                    &dependencies->padding);
      dependencies->miscselect = (miscselect_ & request.miscmask);
      dependencies->miscmask = request.miscmask;
      dependencies->keypolicy = request.keypolicy;

      if (request.keypolicy & kKeypolicyConfigidBitMask) {
        dependencies->configid = configid_;
        dependencies->configsvn = configsvn_;
      } else {
        dependencies->configid.fill(0);
        dependencies->configsvn = 0;
      }
      break;

    case KeyrequestKeyname::REPORT_KEY:
      dependencies->keyname = KeyrequestKeyname::REPORT_KEY;
      dependencies->isvfamilyid.fill(0);
      dependencies->isvextprodid.fill(0);
      dependencies->isvprodid = 0;
      dependencies->isvsvn = 0;
      dependencies->ownerepoch = ownerepoch_;
      dependencies->attributes = attributes_;
      dependencies->attributemask.Clear();
      dependencies->mrenclave = mrenclave_;
      dependencies->mrsigner.fill(0);
      dependencies->keyid = request.keyid;
      dependencies->seal_key_fuses = seal_fuses_;
      dependencies->cpusvn = cpusvn_;
      SetTrivialObjectFromHexString(kHardcodedPkcs15PaddingHex,
                                    &dependencies->padding);
      dependencies->miscselect = miscselect_;
      dependencies->miscmask = 0;
      dependencies->keypolicy = 0;
      dependencies->configid = configid_;
      dependencies->configsvn = configsvn_;
      break;

    default:
      return SgxError(
          SGX_ERROR_INVALID_KEYNAME,
          absl::StrCat("Key name ", static_cast<uint64_t>(request.keyname),
                       " is not supported"));
  }
  return DeriveKey(key_dependencies, key);
}

Status FakeEnclave::GetHardwareReport(const Targetinfo &tinfo,
                                      const Reportdata &reportdata,
                                      Report *report) const {
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
  SecsAttributeSet reserved_attributes =
      ~SecsAttributeSet::GetAllSupportedBits();
  if (tinfo.reserved1 != TrivialZeroObject<decltype(tinfo.reserved1)>() ||
      tinfo.reserved2 != TrivialZeroObject<decltype(tinfo.reserved2)>() ||
      (tinfo.miscselect & ~kValidMiscselectBitmask) != 0 ||
      (tinfo.attributes & reserved_attributes) !=
          TrivialZeroObject<SecsAttributeSet>()) {
    LOG(FATAL) << "Reserved fields/bits in input parameters are not zeroed.";
  }

  report->body.cpusvn = cpusvn_;
  report->body.miscselect = miscselect_;
  report->body.reserved1.fill(0);
  report->body.isvextprodid = isvextprodid_;
  report->body.attributes = attributes_;
  report->body.mrenclave = mrenclave_;
  report->body.reserved2.fill(0);
  report->body.mrsigner = mrsigner_;
  report->body.reserved3.fill(0);
  report->body.configid = configid_;
  report->body.isvprodid = isvprodid_;
  report->body.isvsvn = isvsvn_;
  report->body.configsvn = configsvn_;
  report->body.reserved4.fill(0);
  report->body.isvfamilyid = isvfamilyid_;
  report->body.reportdata = reportdata;
  report->keyid = report_keyid_;

  // Prepare a KeyDependencies struct to generate the appropriate report key.
  // This code is pretty much directly taken from the EREPORT instruction
  // description in the Intel SDM.
  KeyDependencies key_dependencies;
  KeyDependenciesBase *dependencies = &key_dependencies.dependencies;

  dependencies->keyname = KeyrequestKeyname::REPORT_KEY;
  dependencies->isvfamilyid.fill(0);
  dependencies->isvextprodid.fill(0);
  dependencies->isvprodid = 0;
  dependencies->isvsvn = 0;
  dependencies->ownerepoch = ownerepoch_;
  dependencies->attributes = tinfo.attributes;
  dependencies->attributemask.Clear();
  dependencies->mrenclave = tinfo.measurement;
  dependencies->mrsigner.fill(0);
  dependencies->keyid = report_keyid_;
  dependencies->seal_key_fuses = seal_fuses_;
  dependencies->cpusvn = cpusvn_;
  SetTrivialObjectFromHexString(kHardcodedPkcs15PaddingHex,
                                &dependencies->padding);
  dependencies->miscselect = tinfo.miscselect;
  dependencies->miscmask = 0;
  dependencies->keypolicy = 0;
  dependencies->configid = tinfo.configid;
  dependencies->configsvn = tinfo.configsvn;

  SafeBytes<kHardwareKeySize> report_key;
  ASYLO_RETURN_IF_ERROR(DeriveKey(key_dependencies, &report_key));

  // Compute the report MAC. SGX uses CMAC to MAC the contents of the report.
  // The last two fields (KEYID and MAC) from the REPORT struct are not
  // included in the MAC computation.
  if (report->mac.size() != AES_BLOCK_SIZE) {
    return SgxError(
        SGX_ERROR_INVALID_PARAMETER,
        "Size of the mac field in the REPORT structure is incorrect.");
  }

  if (AES_CMAC(report->mac.data(), report_key.data(), report_key.size(),
               reinterpret_cast<uint8_t *>(&report->body),
               sizeof(report->body)) != 1) {
    // Clear-out any leftover state from the output.
    report->mac.Cleanse();
    return SgxError(SGX_ERROR_UNEXPECTED, BsslLastErrorString());
  }
  return absl::OkStatus();
}

Status FakeEnclave::DeriveKey(const KeyDependencies &key_dependencies,
                              HardwareKey *key) const {
  static_assert(HardwareKey::size() == AES_BLOCK_SIZE,
                "Mismatch between kHardwareKeySize and AES_BLOCK_SIZE");

  if (AES_CMAC(key->data(), root_key_.data(), root_key_.size(),
               reinterpret_cast<const uint8_t *>(&key_dependencies),
               sizeof(key_dependencies)) != 1) {
    // Clear-out any leftover state from the output.
    key->Cleanse();
    return SgxError(SGX_ERROR_UNEXPECTED, BsslLastErrorString());
  }
  return absl::OkStatus();
}

}  // namespace sgx
}  // namespace asylo
