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

#ifndef ASYLO_IDENTITY_SGX_FAKE_ENCLAVE_H_
#define ASYLO_IDENTITY_SGX_FAKE_ENCLAVE_H_

#include <vector>

#include "asylo/identity/sgx/hardware_interface.h"
#include "asylo/identity/sgx/identity_key_management_structs.h"
#include "asylo/identity/util/bytes.h"
#include "asylo/identity/util/trivial_object_util.h"
#include <openssl/sha.h>

#ifdef __ASYLO__
#error \
    "Must not link the fake-enclave library into a real or a simulated enclave"
#endif

namespace asylo {
namespace sgx {
// Size of the SGX owner epoch, which is defined to be 16 bytes by the Intel
// Software Developer's Manual (SDM).
constexpr size_t kOwnerEpochSize = 16;

// Mask indicating the SECS attributes bits that the CPU will always include
// while deriving the sealing key. According to Intel SDM, the least-significant
// byte of this mask has a value of 0x3, while all other bytes are set to zero
// (i.e., INIT and DEBUG bits are always included, and other bits are optional).
constexpr SecsAttributeSet kRequiredSealingAttributesMask = {0x3, 0x0};

// The FakeEnclave class implements an enclave-like identity functionality that
// can be utilized by various unit and integration tests.  The class includes
// data members to emulate various SGX-defined measurement registers,
// attributes, etc., as well as many other under-the-hood components such as
// CPUSVN, enclave's current KEYID for reporting purposes, seal-key-fuses, etc.
//
// The class implements a thread-local static pointer called current_, which
// stores the pointer to a fake-enclave instance that represents the "currently
// executing enclave". If current_ is set to nullptr, it indicates that the
// thread is currently not executing inside any enclave. A thread can simulate
// enclave entry by calling the FakeEnclave::EnterEnclave static method.
// Similarly, a thread can simulate enclave exit by calling the
// FakeEnclave::ExitEnclave static method. A thread can get access to the
// pointer to the currently executing method by calling the
// FakeEnclave::GetCurrentEnclave static method.
//
// The FakeEnclave class provides three public methods, GetHardwareRand64,
// GetHardwareKey, and GetHardwareReport. These methods are utilized by the fake
// hardware-interface implementation. Specifically, the fake hardware-interface
// implementation in fake_hardware_interface.cc relies on the enclave pointer in
// current_ to get enclave-specific hardware key and enclave-specific report.
//
// None of the SGX identity libraries directly use the FakeEnclave
// functionality. Those libraries instead utilize the hardware interface
// defined in the hardware_interface.h header. Any unit or integration tests
// that need to test such libraries using the FakeEnclave implementation should
// configure necessary FakeEnclave instances, use the EnterEnclave method to
// simulate entry into an appropriate enclave, and then test out the library
// interface. The fake_hardware_interface_test.cc file can be used as an example
// of how this functionality can be leveraged.
class FakeEnclave {
 public:
  FakeEnclave();
  FakeEnclave(const FakeEnclave &other) = default;
  FakeEnclave &operator=(const FakeEnclave &other) = default;

  // Return a pointer to the current thread-local static-scoped instance of
  // FakeEnclave. The caller does not own the returned pointer, as a copy of the
  // pointer is still retained in the thread-local member current_, and may be
  // returned to other callers of GetCurrent.
  static FakeEnclave *GetCurrentEnclave();

  // Copy the input FakeEnclave value to the current thread-local static-scoped
  // instance of FakeEnclave. If no such instance is allocated, allocate one.
  static void EnterEnclave(const FakeEnclave &value);

  // Free the current thread-local static-scoped instance of FakeEnclave,
  // if one is allocated.
  static void ExitEnclave();

  // Mutators
  void set_mrenclave(const UnsafeBytes<SHA256_DIGEST_LENGTH> &value) {
    mrenclave_ = value;
  }
  void set_mrsigner(const UnsafeBytes<SHA256_DIGEST_LENGTH> &value) {
    mrsigner_ = value;
  }
  void set_isvprodid(uint16_t value) { isvprodid_ = value; }
  void set_isvsvn(uint16_t value) { isvsvn_ = value; }
  void set_attributes(const SecsAttributeSet &value) { attributes_ = value; }
  void set_miscselect(uint32_t value) { miscselect_ = value; }
  void set_cpusvn(const UnsafeBytes<kCpusvnSize> &value) { cpusvn_ = value; }
  void set_report_keyid(const UnsafeBytes<kReportKeyidSize> &value) {
    report_keyid_ = value;
  }
  void set_ownerepoch(const SafeBytes<kOwnerEpochSize> &value) {
    ownerepoch_ = value;
  }
  void set_root_key(const SafeBytes<SHA256_DIGEST_LENGTH> &value) {
    root_key_ = value;
  }
  void set_seal_fuses(const SafeBytes<AES_BLOCK_SIZE> &value) {
    seal_fuses_ = value;
  }

  // Accessors
  const UnsafeBytes<SHA256_DIGEST_LENGTH> &get_mrenclave() {
    return mrenclave_;
  }
  const UnsafeBytes<SHA256_DIGEST_LENGTH> &get_mrsigner() { return mrsigner_; }
  uint16_t get_isvprodid() { return isvprodid_; }
  uint16_t get_isvsvn() { return isvsvn_; }
  const SecsAttributeSet &get_attributes() { return attributes_; }
  uint32_t get_miscselect() { return miscselect_; }
  const UnsafeBytes<kCpusvnSize> &get_cpusvn() { return cpusvn_; }
  const UnsafeBytes<kReportKeyidSize> &get_report_keyid() {
    return report_keyid_;
  }
  const SafeBytes<kOwnerEpochSize> &get_ownerepoch() { return ownerepoch_; }
  const SafeBytes<SHA256_DIGEST_LENGTH> &get_root_key() { return root_key_; }
  const SafeBytes<AES_BLOCK_SIZE> &get_seal_fuses() { return seal_fuses_; }

  // Initialize data members that represent the enclave's identity to random
  // values.
  void SetRandomIdentity();

  // Equality operator--only needed for testing purposes.
  bool operator==(const FakeEnclave &rhs) const;

  // Equality operator--only needed for testing purposes.
  bool operator!=(const FakeEnclave &rhs) const;

  // Fake implementation of RdRand64.
  static bool GetHardwareRand64(uint64_t *value);

  // Fake implementation of the SGX EGETKEY instruction.
  bool GetHardwareKey(const Keyrequest &request, HardwareKey *key);

  // Fake implementation of the SGX EREPORT instruction.
  bool GetHardwareReport(const Targetinfo &tinfo, const Reportdata &reportdata,
                         Report *report);

 private:
  // The Intel SDM (Software Developer's Manual) refers to a structure
  // called the Key Dependencies structure that the CPU uses for deriving
  // various keys. This structure is not explicitly documented in the SDM,
  // however, the SDM is very explicit about how the CPU uses this structure
  // for its key-derivation operations. The following structure is inferred
  // from the various descriptions in the SDM.
  //
  // This structure is only used for the fake implementation, and the
  // derivations performed using this structure will never be directly compared
  // against those performed by a real CPU. Consequently, it is OK even if this
  // structure deviates from the actual structure used by the CPU internally.
  // Also, its alignment and packing does not matter.
  //
  // While a fake key-derivation implementation could be created without using
  // this structure, it is probably best to follow the pseudo-code provided in
  // the Intel SDM as much as possible.
  struct KeyDependencies {
    KeyrequestKeyname keyname;
    uint16_t isvprodid;
    uint16_t isvsvn;
    SafeBytes<kOwnerEpochSize> ownerepoch;
    SecsAttributeSet attributes;
    SecsAttributeSet attributemask;
    UnsafeBytes<SHA256_DIGEST_LENGTH> mrenclave;
    UnsafeBytes<SHA256_DIGEST_LENGTH> mrsigner;
    UnsafeBytes<kKeyrequestKeyidSize> keyid;
    SafeBytes<AES_BLOCK_SIZE> seal_key_fuses;
    UnsafeBytes<kCpusvnSize> cpusvn;

    // The Intel SDM hints at a padding field at this offset in this structure,
    // which, the SDM says, is copied from the SECS. However the SDM does not
    // describe any SECS.PADDING field. It appears that this field is used as a
    // "security measure"--if somehow unused bits in SECS got used (due to a
    // bug, or attack, or ...), the key would be affected. Since there is no
    // such security concern regarding the fake implementation, the padding
    // field is skipped in this structure.

    uint32_t miscselect;
    uint32_t miscmask;
  } __attribute__((packed));

  // The Intel SDM  refers to a DeriveKey function, without describing the exact
  // cryptographic operation performed by that function. The function takes a
  // KeyDependencies structure as the only input, which may or may not contain
  // any randomness (depending on the key being derived). Consequently, it
  // appears that the CPU must be providing some other "root key" as an input to
  // this KDF (key-derivation function). The fake key-derivation function uses
  // AES-128-CMAC as its KDF, as based on the description of the EGETKEY
  // pseudo-code, it looks like this key-derivation function returns a 128-bit
  // key. The fake key-derivation function also uses the "root key" stored in
  // the FakeEnclave signleton as a key for this KDF.
  bool DeriveKey(const KeyDependencies &dependencies, HardwareKey *key);

  // SGX-defined MRENCLAVE value of this fake enclave.
  UnsafeBytes<SHA256_DIGEST_LENGTH> mrenclave_;

  // SGX-defined MRSIGNER value of this fake enclave.
  UnsafeBytes<SHA256_DIGEST_LENGTH> mrsigner_;

  // SGX-defined ISVPRODID value of this fake enclave.
  uint16_t isvprodid_;

  // SGX-defined ISVSVN value of this fake enclave.
  uint16_t isvsvn_;

  // SGX-defined ATTRIBUTES value of this fake enclave.
  SecsAttributeSet attributes_;

  // SGX-defined MISCSELECT value of this fake enclave.
  uint32_t miscselect_;

  // SGX-defined CPUSVN value.
  UnsafeBytes<kCpusvnSize> cpusvn_;

  // SGX-defined REPORT KEYID value.
  UnsafeBytes<kReportKeyidSize> report_keyid_;

  // SGX-defined OWNEREPOCH value.
  SafeBytes<kOwnerEpochSize> ownerepoch_;

  // Key at the root of the enclave's key hierarchy. All enclave-specific
  // keys are derived from this key. The Intel SDM does not directly reference
  // this key, nor does it mention its size.
  SafeBytes<SHA256_DIGEST_LENGTH> root_key_;

  // Value of the "Seal fuses" referenced by the EREPORT/EGETKEY pseudo code.
  // The SDM describes this as a "package-wide control register that is 128 bits
  // in size.
  SafeBytes<AES_BLOCK_SIZE> seal_fuses_;

  // Per-thread current fake enclave
  thread_local static FakeEnclave *current_;
};

// Constructs a randomly-initialized FakeEnclave. This factory object is useful
// for creating a random FakeEnclave singleton.
struct RandomFakeEnclaveFactory {
  using value_type = FakeEnclave;
  static FakeEnclave *Construct() {
    FakeEnclave *enclave = new FakeEnclave();
    enclave->SetRandomIdentity();
    return enclave;
  }
  static void Destruct(FakeEnclave *enclave) { delete enclave; }
};

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_FAKE_ENCLAVE_H_
