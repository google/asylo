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

#ifndef ASYLO_IDENTITY_SGX_IDENTITY_KEY_MANAGEMENT_STRUCTS_H_
#define ASYLO_IDENTITY_SGX_IDENTITY_KEY_MANAGEMENT_STRUCTS_H_

#include "absl/base/attributes.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/sgx/secs_attributes.h"
#include "asylo/identity/util/aligned_object_ptr.h"
#include <openssl/aes.h>
#include <openssl/sha.h>

// This file defines SGX architectural structures that pertain to the identity
// and key-management portions of the SGX architecture. These structures are
// taken directly from the Intel SDM (Software Developer's Manual) and the
// various structures and fields in these structures are named to match the
// names of the corresponding structures and fields in the Intel SDM. The Intel
// SDM uses single words to describe a structure or a field therein irrespective
// of whether they comprise of multiple English words. Consequently, these
// names are treated as single words and then standard
// capitalization/hyphenation rules are applied to those words. For example, the
// Intel SDM defines a structure called REPORTDATA. This file defines this
// structure as Reportdata. The expected size of this structure is defined by
// the constant kReportdataSize.
//
// Readers are referred to Intel SDM vol 3 for the explanation of these
// structures, their fields, and their interactions with x86-64 instruction set
// in general, and SGX instruction set in particular.

namespace asylo {
namespace sgx {

// The following constants are global constants, in the sense that they
// are not tied to a particular SGX structure.

// Size of RSA3072 Modulus
constexpr int kRsa3072ModulusSize = 384;

// Size of MACs used in SGX architecture. According to the Intel SDM
// (Software Developer's Manual) SGX uses AES-based MACs (either GCM or CMAC),
// and consequently this size is 16 bytes.
constexpr int kSgxMacSize = AES_BLOCK_SIZE;

// Size of the CPU's SVN (Security Version Number). The value of CPU SVN
// is used by the CPU to specialize/access-control various SGX keys.
constexpr int kCpusvnSize = 16;

// The following constants are specific to the SIGSTRUCT, and are taken
// from the Intel SDM.

// Size of the two SIGSTRUCT headers (defined below).
constexpr int kSigstructHeaderSize = 16;

// DATE structure defines the format of the "date" field embedded in the
// SIGSTRUCT (defined below)
struct Date {
  uint16_t year;
  uint8_t month;
  uint8_t day;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Date) == 4, "Size of struct Date is incorrect");

// SIGSTRUCT defines the enclave signature structure, which is provided
// as an input to the ENCLS[EINIT] instruction.
//
// The structure is stored and handled by the untrusted part of the program
// and consequently, none of the fields in this structure are
// security-sensitive. Consequently, all byte-array-type members of this
// structure are instantiated using the UnsafeBytes template.
struct Sigstruct {
  UnsafeBytes<kSigstructHeaderSize> header;
  uint32_t vendor;
  Date date;
  UnsafeBytes<kSigstructHeaderSize> header2;
  uint32_t swdefined;
  UnsafeBytes<84> reserved1;  // Field size taken from the Intel SDM.
  UnsafeBytes<kRsa3072ModulusSize> modulus;
  uint32_t exponent;
  UnsafeBytes<kRsa3072ModulusSize> signature;
  uint32_t miscselect;
  uint32_t miscmask;
  UnsafeBytes<20> reserved2;  // Field size taken from the Intel SDM.
  SecsAttributeSet attributes;
  SecsAttributeSet attributemask;
  UnsafeBytes<SHA256_DIGEST_LENGTH> enclavehash;
  UnsafeBytes<32> reserved3;  // Field size taken from the Intel SDM.
  uint16_t isvprodid;
  uint16_t isvsvn;
  UnsafeBytes<12> reserved4;  // Field size taken from the Intel SDM.
  UnsafeBytes<kRsa3072ModulusSize> q1;
  UnsafeBytes<kRsa3072ModulusSize> q2;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Sigstruct) == 1808,
              "Size of struct Sigstruct is incorrect");

// Aligned SIGSTRUCT structure. SGX architecture requires this structure
// to be aligned on a 4096-byte boundary.
using AlignedSigstructPtr = AlignedObjectPtr<Sigstruct, 4096>;

// KEYNAME defines the x86-64 architectural names for the various keys
// that are potentially available to an enclave. The base type of this enum
// class is uint16_t to make it compatible with the KEREQUEST struct defined
// below.
enum class KeyrequestKeyname : uint16_t {
  EINITTOKEN_KEY = 0,
  PROVISION_KEY = 1,
  PROVISION_SEAL_KEY = 2,
  REPORT_KEY = 3,
  SEAL_KEY = 4
};

// Size of the KEYID field in the KEYREQUEST struct. Taken from the Intel SDM.
constexpr int kKeyrequestKeyidSize = 32;

// KEYPOLICY is a 16-bit bitfield indicating what parts of enclave measurement
// should be included in derivation of an SGX key. Bit 0 indicates whether
// MRENCLAVE should be included, whereas bit 1 indicates whether MRSIGNER
// should be included. All the remaining bits of KEYPOLICY are reserved.
//
// The following constants define masks for the non-reserved bits of KEYPOLICY.
constexpr uint16_t kKeypolicyMrenclaveBitMask = 0x1;
constexpr uint16_t kKeypolicyMrsignerBitMask = 0x2;

// KEYREQUEST structure is used by an enclave to request various hardware
// keys from the CPU, and is provided as an input to the ENCLU[EGETKEY]
// instruction.
//
// The KEYREQUEST structure itself does not contain any security-sensitive or
// secret values (although the key generated by the ENCLU[EGETKEY] instruction
// is typically security-sensitive). Consequently, all byte-array-type members
// of this structure are instantiated using the UnsafeBytes template.
struct Keyrequest {
  KeyrequestKeyname keyname;
  uint16_t keypolicy;
  uint16_t isvsvn;
  UnsafeBytes<2> reserved1;  // Field size taken from the Intel SDM.
  UnsafeBytes<kCpusvnSize> cpusvn;
  SecsAttributeSet attributemask;
  UnsafeBytes<kKeyrequestKeyidSize> keyid;
  uint32_t miscmask;
  UnsafeBytes<436> reserved2;  // Field size taken from the Intel SDM.
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Keyrequest) == 512,
              "Size of struct Keyrequest is incorrect");

// Aligned KEYREQUEST structure. SGX architecture requires this structure
// to be aligned on a 512-byte boundary.
using AlignedKeyrequestPtr = AlignedObjectPtr<Keyrequest, 512>;

// TARGETINFO structure is used by software to define the identity of the
// enclave to which an enclave identity report should be targeted. This
// structure is provided as an input to the ENCLU[EREPORT] instruction.
//
// The TARGETINFO structure does not contain any security-sensitive/secret
// values. Consequently, all byte-array-type members of this structure are
// instantiated using the UnsafeBytes template.
struct Targetinfo {
  UnsafeBytes<SHA256_DIGEST_LENGTH> measurement;
  SecsAttributeSet attributes;
  UnsafeBytes<4> reserved1;  // Field size taken from the Intel SDM.
  uint32_t miscselect;
  UnsafeBytes<456> reserved2;  // Field size taken from the Intel SDM.
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Targetinfo) == 512,
              "Size of struct Targetinfo is incorrect");

// Aligned TARGETINFO structure. SGX architecture requires this structure
// to be aligned on a 512-byte boundary.
using AlignedTargetinfoPtr = AlignedObjectPtr<Targetinfo, 512>;

// Size of REPORTDATA field in the REPORT and REPORTDATA structs defined below.
constexpr int kReportdataSize = 64;

// REPORTDATA structure holds kReportdataSize bytes of unstructured data.
// This structure is provided as input to the EREPORT instruction. The EREPORT
// instruction includes the unstructured data from this input in its output
// structure (REPORT). The contents of this structure are not secret, and
// consequently, the data-safety policy is set to DataSafety::UNSAFE.
struct Reportdata {
  UnsafeBytes<kReportdataSize> data;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Reportdata) == kReportdataSize,
              "Size of struct Reportdata is incorrect");

// Aligned REPORTDATA structure. SGX architecture requires this structure to be
// aligned on a 128-byte boundary.
using AlignedReportdataPtr = AlignedObjectPtr<Reportdata, 128>;

// Size of KEYID field in the REPORT struct defined below.
constexpr int kReportKeyidSize = 32;

static_assert(kReportKeyidSize == kKeyrequestKeyidSize,
              "KEYID size for REPORT and KEYREQUEST structs is not the same");

// REPORT structure acts as a locally-verifiable assertion of an enclave's
// identity, and is an output from the ENCLU[EREPORT] instruction.
//
// The REPORT structure does not contain any security-sensitive/secret values.
// Consequently, all byte-array-type members of this structure are instantiated
// using the UnsafeBytes template.
struct Report {
  UnsafeBytes<kCpusvnSize> cpusvn;
  uint32_t miscselect;
  UnsafeBytes<28> reserved1;  // Field size taken from the Intel SDM.
  SecsAttributeSet attributes;
  UnsafeBytes<SHA256_DIGEST_LENGTH> mrenclave;
  UnsafeBytes<32> reserved2;  // Field size taken from the Intel SDM.
  UnsafeBytes<SHA256_DIGEST_LENGTH> mrsigner;
  UnsafeBytes<96> reserved3;  // Field size taken from the Intel SDM.
  uint16_t isvprodid;
  uint16_t isvsvn;
  UnsafeBytes<60> reserved4;  // Field size taken from the Intel SDM.
  Reportdata reportdata;
  UnsafeBytes<kReportKeyidSize> keyid;
  UnsafeBytes<kSgxMacSize> mac;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Report) == 432, "Size of struct Report is incorrect");

// Aligned REPORT structure. SGX architecture requires this structure
// to be aligned on a 512-byte boundary.
using AlignedReportPtr = AlignedObjectPtr<Report, 512>;

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_SGX_IDENTITY_KEY_MANAGEMENT_STRUCTS_H_
