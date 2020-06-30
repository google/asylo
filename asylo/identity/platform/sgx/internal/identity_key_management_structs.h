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

#ifndef ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_IDENTITY_KEY_MANAGEMENT_STRUCTS_H_
#define ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_IDENTITY_KEY_MANAGEMENT_STRUCTS_H_

#include <openssl/aes.h>

#include <type_traits>

#include "absl/base/attributes.h"
#include "asylo/crypto/sha256_hash.h"
#include "asylo/crypto/util/bytes.h"
#include "asylo/identity/additional_authenticated_data_generator.h"
#include "asylo/identity/platform/sgx/internal/secs_attributes.h"
#include "asylo/util/aligned_object_ptr.h"

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
// the constant kReportdataSize. Note that all fixed-sized bytes fields are
// represented using the UnsafeBytes template, as none of the fields are
// security-sensitive (they do not require memory cleansing).
//
// Readers are referred to Intel SDM vol 3 for the explanation of the
// architectural structures, their fields, and their interactions with x86-64
// instruction set in general, and SGX instruction set in particular.
//
// This file also defines several SGX structures that are non-architectural.
// These structures are just providing for convenience of grouping related
// fields together.

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

// Size of a Platform Provisioning ID (PPID).
constexpr int kPpidSize = 16;

// Size of the CPU's SVN (Security Version Number). The value of CPU SVN
// is used by the CPU to specialize/access-control various SGX keys.
constexpr int kCpusvnSize = 16;

// The size of an Fmspc's |value| field.
constexpr int kFmspcSize = 6;

// The following constants are specific to the SIGSTRUCT architectural
// structure, and are taken from the Intel SDM.

// Size of the two SIGSTRUCT headers (defined below).
constexpr int kSigstructHeaderSize = 16;

// Size of CONFIGID.
constexpr int kConfigidSize = 64;

// Size of ISVFAMILYID.
constexpr int kIsvfamilyidSize = 16;

// Size of ISVEXTPRODID.
constexpr int kIsvextprodidSize = 16;

// The SGX architecture defines the size of all hardware keys to be 128 bits
// (16 bytes), which is same as size of an AES block.
constexpr size_t kHardwareKeySize = AES_BLOCK_SIZE;

// Type alias used for holding a hardware key. It uses the SafeBytes
// template to ensure proper cleansing after the object goes out of scope.
using HardwareKey = SafeBytes<kHardwareKeySize>;

static_assert(sizeof(HardwareKey) == kHardwareKeySize,
              "Size of the struct HardwareKey is incorrect.");

// The SGX architecture requires that the output memory address passed into the
// EGETKEY instruction must be aligned on a 16-byte boundary.
using AlignedHardwareKeyPtr = AlignedObjectPtr<HardwareKey, 16>;

// Date defines the format of the "date" field embedded in a SIGSTRUCT.
//
// Note that this is not an architectural structure.
struct Date {
  uint16_t year;
  uint8_t month;
  uint8_t day;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Date) == 4, "Size of Date struct is incorrect");

// The set of fields that define the header of a SIGSTRUCT. This is a subset of
// the fields in SIGSTRUCT that are signed. See SigstructSigningData for the
// full set of fields that are signed.
//
// Note that this is not an architectural structure.
struct SigstructHeader {
  UnsafeBytes<kSigstructHeaderSize> header1;
  uint32_t vendor;
  Date date;
  UnsafeBytes<kSigstructHeaderSize> header2;
  uint32_t swdefined;
  UnsafeBytes<84> reserved1;  // Field size taken from the Intel SDM.
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(SigstructHeader) == 128,
              "Size of struct SigstructHeader is incorrect");

// The set of fields that define the body of a SIGSTRUCT. This is a subset of
// the fields in SIGSTRUCT that are signed. See SigstructSigningData for the
// full set of fields that are signed.
//
// Note that this is not an architectural structure.
struct SigstructBody {
  uint32_t miscselect;
  uint32_t miscmask;
  UnsafeBytes<4> reserved1;  // Field size taken from the Intel SDM.
  UnsafeBytes<kIsvfamilyidSize> isvfamilyid;
  SecsAttributeSet attributes;
  SecsAttributeSet attributemask;
  UnsafeBytes<kSha256DigestLength> enclavehash;
  UnsafeBytes<16> reserved2;  // Field size taken from the Intel SDM.
  UnsafeBytes<kIsvextprodidSize> isvextprodid;
  uint16_t isvprodid;
  uint16_t isvsvn;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(SigstructBody) == 128,
              "Size of struct SigstructBody is incorrect");

// The set of fields that comprise the RSA-3072 public key stored in SIGSTRUCT.
// The exponent field must always be 3.
//
// Note that this is not an architectural structure.
struct Rsa3072PublicKey {
  UnsafeBytes<kRsa3072ModulusSize> modulus;
  uint32_t exponent;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Rsa3072PublicKey) == 388,
              "Size of struct Rsa3072PublicKey is incorrect");

// The subset of fields in SIGSTRUCT that are signed. A signature over this
// structure is placed in the signature field of the SIGSTRUCT.
//
// Note that although this structure is architectural, it does not require
// alignment because it is not used as an input to any SGX instruction.
struct SigstructSigningData {
  SigstructHeader header;
  SigstructBody body;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(SigstructSigningData) == 256,
              "Size of struct SigstructSigningData is incorrect");

// Defines the SIGSTRUCT structure, which represents the enclave signature
// structure. A SIGSTRUCT is provided as an input to the ENCLS[EINIT]
// instruction.
struct Sigstruct {
  SigstructHeader header;
  Rsa3072PublicKey public_key;
  UnsafeBytes<kRsa3072ModulusSize> signature;
  SigstructBody body;
  UnsafeBytes<12> reserved1;  // Field size taken from the Intel SDM.
  UnsafeBytes<kRsa3072ModulusSize> q1;
  UnsafeBytes<kRsa3072ModulusSize> q2;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Sigstruct) == 1808,
              "Size of struct Sigstruct is incorrect");

// Aligned SIGSTRUCT structure. SGX architecture requires this structure
// to be aligned on a 4096-byte boundary.
using AlignedSigstructPtr = AlignedObjectPtr<Sigstruct, 4096>;

// Defines the KEYREQUEST KeyNames enumeration, which is the set of x86-64
// architectural names for the various keys that are available to be requested
// via a KEYREQUEST. The base type of this enum class is uint16_t to make it
// compatible with the KeyRequest structure defined below.
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
// should be included in derivation of an SGX key.
//  * Bit 0: Indicates whether MRENCLAVE should be included.
//  * Bit 1: Indicates whether MRSIGNER should be included.
//  * Bit 2: Indicates whether ISVPRODID should be omitted.
//  * Bit 3: Indicates whether CONFIGID and CONFIGSVN should be included.
//  * Bit 4: Indicates whether ISVFAMILYID should be included.
//  * Bit 5: Indicates whether ISVEXTPRODID should be included.
//
// All the remaining bits of KEYPOLICY are reserved.
//
// The following constants define masks for the non-reserved bits of KEYPOLICY.
constexpr uint16_t kKeypolicyMrenclaveBitMask = 0x1;
constexpr uint16_t kKeypolicyMrsignerBitMask = 0x2;
constexpr uint16_t kKeypolicyNoisvprodidBitMask = 0x4;
constexpr uint16_t kKeypolicyConfigidBitMask = 0x8;
constexpr uint16_t kKeypolicyIsvfamilyidBitMask = 0x10;
constexpr uint16_t kKeypolicyIsvextprodidBitMask = 0x20;

// The following constants define the logical groupings of KEYPOLICY bits.

// KEYPOLICY bits that can only be set if the KSS attribute is set.
constexpr uint16_t kKeypolicyKssBits =
    kKeypolicyNoisvprodidBitMask | kKeypolicyConfigidBitMask |
    kKeypolicyIsvfamilyidBitMask | kKeypolicyIsvextprodidBitMask;

// All non-reserved KEYPOLICY bits.
constexpr uint16_t kKeypolicyAllBits =
    kKeypolicyMrenclaveBitMask | kKeypolicyMrsignerBitMask | kKeypolicyKssBits;

// Reserved KEYPOLICY bits.
constexpr uint16_t kKeypolicyReservedBits = ~kKeypolicyAllBits;

// Defines the KEYREQUEST architectural structure, which is used by an enclave
// to request various hardware keys from the CPU. A KEYREQUEST is provided as an
// input to the ENCLU[EGETKEY] instruction.
struct Keyrequest {
  KeyrequestKeyname keyname;
  uint16_t keypolicy;
  uint16_t isvsvn;
  UnsafeBytes<2> reserved1;  // Field size taken from the Intel SDM.
  UnsafeBytes<kCpusvnSize> cpusvn;
  SecsAttributeSet attributemask;
  UnsafeBytes<kKeyrequestKeyidSize> keyid;
  uint32_t miscmask;
  uint16_t configsvn;
  UnsafeBytes<434> reserved2;  // Field size taken from the Intel SDM.
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Keyrequest) == 512,
              "Size of struct Keyrequest is incorrect");

// Aligned KEYREQUEST structure. SGX architecture requires this structure
// to be aligned on a 512-byte boundary.
using AlignedKeyrequestPtr = AlignedObjectPtr<Keyrequest, 512>;

// Defines the TARGETINFO architectural structure, which is used by software to
// define the identity of the enclave to which an enclave identity report should
// be targeted. A TARGETINFO is one of the inputs that is provided to the
// ENCLU[EREPORT] instruction.
struct Targetinfo {
  UnsafeBytes<kSha256DigestLength> measurement;
  SecsAttributeSet attributes;
  UnsafeBytes<2> reserved1;  // Field size taken from the Intel SDM.
  uint16_t configsvn;
  uint32_t miscselect;
  UnsafeBytes<8> reserved2;  // Field size taken from the Intel SDM.
  UnsafeBytes<kConfigidSize> configid;
  UnsafeBytes<384> reserved3;  // Field size take from the Intel SDM.
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Targetinfo) == 512,
              "Size of struct Targetinfo is incorrect");

// Aligned TARGETINFO structure. SGX architecture requires this structure
// to be aligned on a 512-byte boundary.
using AlignedTargetinfoPtr = AlignedObjectPtr<Targetinfo, 512>;

// Size of REPORTDATA field in the REPORT and REPORTDATA structs defined below.
constexpr int kReportdataSize = 64;

static_assert(kReportdataSize == kAdditionalAuthenticatedDataSize,
              "Report data must be able to hold additional authenticated data");

// Defines the REPORTDATA architectural structure, which holds kReportdataSize
// bytes of unstructured data. A REPORTDATA is one of the inputs that is
// provided to the EREPORT instruction. The EREPORT instruction includes the
// unstructured data from this input in its output structure (REPORT).
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

// Defines the portion of a REPORT architectural structure which will be MACed.
// The ReportBody describes various attestable attributes and measurements of a
// running enclave.
struct ReportBody {
  UnsafeBytes<kCpusvnSize> cpusvn;
  uint32_t miscselect;
  UnsafeBytes<12> reserved1;  // Field size taken from the Intel SDM.
  UnsafeBytes<kIsvextprodidSize> isvextprodid;
  SecsAttributeSet attributes;
  UnsafeBytes<kSha256DigestLength> mrenclave;
  UnsafeBytes<32> reserved2;  // Field size taken from the Intel SDM.
  UnsafeBytes<kSha256DigestLength> mrsigner;
  UnsafeBytes<32> reserved3;  // Field size taken from the Intel SDM.
  UnsafeBytes<kConfigidSize> configid;
  uint16_t isvprodid;
  uint16_t isvsvn;
  uint16_t configsvn;
  UnsafeBytes<42> reserved4;  // Field size taken from the Intel SDM.
  UnsafeBytes<kIsvfamilyidSize> isvfamilyid;
  Reportdata reportdata;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(ReportBody) == 384,
              "Size of struct ReportBody is incorrect");

// Defines the REPORT architectural structure, which acts as a
// locally-verifiable assertion of an enclave's identity. REPORT is an output
// from the ENCLU[EREPORT] instruction.
struct Report {
  ReportBody body;
  UnsafeBytes<kReportKeyidSize> keyid;
  UnsafeBytes<kSgxMacSize> mac;
} ABSL_ATTRIBUTE_PACKED;

static_assert(sizeof(Report) == 432, "Size of struct Report is incorrect");

// Aligned REPORT structure. SGX architecture requires this structure
// to be aligned on a 512-byte boundary.
using AlignedReportPtr = AlignedObjectPtr<Report, 512>;

static_assert(std::is_trivial<Date>::value, "Date is not a trivial type");
static_assert(std::is_trivial<SigstructHeader>::value,
              "SigstructHeader is not a trivial type");
static_assert(std::is_trivial<SigstructBody>::value,
              "SigstructBody is not a trivial type");
static_assert(std::is_trivial<Rsa3072PublicKey>::value,
              "Rsa3072PublicKey is not a trivial type");
static_assert(std::is_trivial<SigstructSigningData>::value,
              "SigstructSigningData is not a trivial type");
static_assert(std::is_trivial<Sigstruct>::value,
              "Sigstruct is not a trivial type");
static_assert(std::is_trivial<Keyrequest>::value,
              "Keyrequest is not a trivial type");
static_assert(std::is_trivial<Targetinfo>::value,
              "Targetinfo is not a trivial type");
static_assert(std::is_trivial<Reportdata>::value,
              "Reportdata is not a trivial type");
static_assert(std::is_trivial<ReportBody>::value,
              "ReportBody is not a trivial type");
static_assert(std::is_trivial<Report>::value, "Report is not a trivial type");

}  // namespace sgx
}  // namespace asylo

#endif  // ASYLO_IDENTITY_PLATFORM_SGX_INTERNAL_IDENTITY_KEY_MANAGEMENT_STRUCTS_H_
