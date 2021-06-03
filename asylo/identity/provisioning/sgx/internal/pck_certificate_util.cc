/*
 *
 * Copyright 2019 Asylo authors
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

#include "asylo/identity/provisioning/sgx/internal/pck_certificate_util.h"

#include <endian.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include <google/protobuf/util/message_differencer.h>
#include "absl/base/call_once.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/hash/hash.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/types/span.h"
#include "asylo/crypto/asn1.h"
#include "asylo/crypto/asn1_schema.h"
#include "asylo/crypto/certificate.pb.h"
#include "asylo/crypto/certificate_interface.h"
#include "asylo/crypto/certificate_util.h"
#include "asylo/crypto/util/byte_container_view.h"
#include "asylo/crypto/x509_certificate.h"
#include "asylo/util/logging.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/machine_configuration.pb.h"
#include "asylo/identity/provisioning/sgx/internal/container_util.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.h"
#include "asylo/identity/provisioning/sgx/internal/platform_provisioning.pb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.h"
#include "asylo/identity/provisioning/sgx/internal/tcb.pb.h"
#include "asylo/util/status.h"
#include "asylo/util/status_helpers.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

namespace asylo {
namespace sgx {
namespace {

// Possible SGX Type extension values.
enum class SgxTypeRaw : uint8_t {
  kStandard = 0,
};

// Whether an extension is required or optional.
enum class Optionality { REQUIRED, OPTIONAL };

// Information needed to read a particular extension.
struct ReadInfo {
  // The function used to read the ASN.1 value.
  std::function<Status(const Asn1Value &)> read_function;

  // Whether the extension is required or optional.
  Optionality optionality;
};

// Returns an OBJECT IDENTIFIER for |oid_string|. Crashes the program on
// failure.
ObjectId CreateOidOrDie(const std::string &oid_string);

// Contains object identifiers for components of the SGX extensions. See
// https://download.01.org/intel-sgx/dcap-1.2/linux/docs/Intel_SGX_PCK_Certificate_CRL_Spec-1.1.pdf.
struct SgxOidsStruct {
  ObjectId sgx_extensions = CreateOidOrDie("1.2.840.113741.1.13.1");
  ObjectId ppid = CreateOidOrDie("1.2.840.113741.1.13.1.1");
  ObjectId tcb = CreateOidOrDie("1.2.840.113741.1.13.1.2");
  ObjectId sgx_tcb_comp_svns[kTcbComponentsSize] = {
      CreateOidOrDie("1.2.840.113741.1.13.1.2.1"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.2"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.3"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.4"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.5"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.6"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.7"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.8"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.9"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.10"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.11"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.12"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.13"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.14"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.15"),
      CreateOidOrDie("1.2.840.113741.1.13.1.2.16")};
  ObjectId pce_svn = CreateOidOrDie("1.2.840.113741.1.13.1.2.17");
  ObjectId cpu_svn = CreateOidOrDie("1.2.840.113741.1.13.1.2.18");
  ObjectId pce_id = CreateOidOrDie("1.2.840.113741.1.13.1.3");
  ObjectId fmspc = CreateOidOrDie("1.2.840.113741.1.13.1.4");
  ObjectId sgx_type = CreateOidOrDie("1.2.840.113741.1.13.1.5");
};

// Converts |sgx_type| to a RawSgxType.
StatusOr<SgxTypeRaw> ToRawSgxType(SgxType sgx_type) {
  switch (sgx_type) {
    case SgxType::STANDARD:
      return SgxTypeRaw::kStandard;
    default:
      return Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("No known ENUMERATED value for SgxType: ", sgx_type));
  }
}

// Converts |raw| to an SgxType.
StatusOr<SgxType> FromRawSgxType(std::underlying_type<SgxTypeRaw>::type raw) {
  using UnderlyingType = std::underlying_type<SgxTypeRaw>::type;
  switch (raw) {
    case static_cast<UnderlyingType>(SgxTypeRaw::kStandard):
      return SgxType::STANDARD;
  }
  return Status(absl::StatusCode::kInvalidArgument,
                absl::StrFormat("Unknown SGX Type code: %d", raw));
}

ObjectId CreateOidOrDie(const std::string &oid_string) {
  return ObjectId::CreateFromOidString(oid_string).value();
}

// Returns a singleton instance of SgxOidsStruct.
const SgxOidsStruct &GetSgxOids() {
  static const SgxOidsStruct *oids = new SgxOidsStruct;
  return *oids;
}

// If |asn1| is an OCTET STRING with size |expected_size|, returns its octets.
// Otherwise, returns an error.
StatusOr<std::vector<uint8_t>> ReadOctetStringWithSize(const Asn1Value &asn1,
                                                       size_t expected_size) {
  std::vector<uint8_t> bytes;
  ASYLO_ASSIGN_OR_RETURN(bytes, asn1.GetOctetString());
  if (bytes.size() != expected_size) {
    return Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("Expected a container of size %d, found size %d",
                        expected_size, bytes.size()));
  }
  return bytes;
}

// Returns a schema for a sequence of (OID, ANY) pairs with a minimum length of
// one.
const Asn1Schema<std::vector<std::tuple<ObjectId, Asn1Value>>>
    &OidAnySequenceSchema() {
  static const auto *kSchema =
      CHECK_NOTNULL(Asn1SequenceOf(Asn1Sequence(Asn1ObjectId(), Asn1Any()),
                                   /*min_size=*/1))
          .release();
  return *kSchema;
}

// For each (OID, ASN.1 value) pair in |sequence|, ReadOidAnySequence() calls
// the function in |read_infos| corresponding to the OID on the ASN.1 value.
// ReadOidAnySequence() fails if:
//
//   * Any OID appears more than once in |sequence|.
//   * Any OID in |sequence| is not a key in |read_infos|.
//   * Any of the calls to the functions in |read_infos| returns a non-OK
//     status.
//   * An OID in |read_infos| is marked as REQUIRED but is not found in
//     |sequence|.
Status ReadOidAnySequence(
    absl::flat_hash_map<ObjectId, ReadInfo> read_infos,
    const std::vector<std::tuple<ObjectId, Asn1Value>> &sequence) {
  absl::flat_hash_set<ObjectId> found_oids;
  std::vector<std::string> errors;
  for (auto pair : sequence) {
    ObjectId oid;
    Asn1Value asn1;
    std::tie(oid, asn1) = std::move(pair);
    auto oid_string_result = oid.GetOidString();
    std::string oid_string = oid_string_result.ok() ? oid_string_result.value()
                                                    : "<could not print OID>";
    if (!found_oids.insert(oid).second) {
      errors.push_back(absl::StrCat("Found repeated OID: ", oid_string));
      continue;
    }
    const auto it = read_infos.find(oid);
    if (it == read_infos.end()) {
      auto oid_string_result = oid.GetOidString();
      errors.push_back(absl::StrCat("Unexpected OID: ", oid_string));
      continue;
    }
    Status read_status = WithContext(
        it->second.read_function(asn1),
        absl::StrFormat("Error reading value for OID %s: ", oid_string));
    if (!read_status.ok()) {
      if (read_status.code() == absl::StatusCode::kInvalidArgument) {
        errors.push_back(std::string(read_status.message()));
      } else {
        return read_status;
      }
    }
  }
  for (auto pair : read_infos) {
    ObjectId oid;
    ReadInfo read_info;
    std::tie(oid, read_info) = std::move(pair);
    if (read_info.optionality == Optionality::REQUIRED &&
        !found_oids.contains(oid)) {
      auto oid_string_result = oid.GetOidString();
      errors.push_back(oid_string_result.ok()
                           ? absl::StrCat("Missing extension with OID ",
                                          oid_string_result.value())
                           : "Missing extension");
    }
  }
  return errors.empty() ? absl::OkStatus()
                        : absl::InvalidArgumentError(absl::StrCat(
                              "Encountered the following errors:\n  ",
                              absl::StrJoin(errors, "\n  ")));
}

// Validates an SgxExtensions object.
Status ValidateSgxExtensions(const SgxExtensions &extensions) {
  ASYLO_RETURN_IF_ERROR(ValidatePpid(extensions.ppid));
  ASYLO_RETURN_IF_ERROR(ValidateTcb(extensions.tcb));
  ASYLO_RETURN_IF_ERROR(ValidateCpuSvn(extensions.cpu_svn));
  ASYLO_RETURN_IF_ERROR(ValidatePceId(extensions.pce_id));
  ASYLO_RETURN_IF_ERROR(ValidateFmspc(extensions.fmspc));
  if (!SgxType_IsValid(extensions.sgx_type) ||
      extensions.sgx_type == SgxType::SGX_TYPE_UNKNOWN) {
    return absl::InvalidArgumentError(
        absl::StrCat("Invalid SgxType: ", extensions.sgx_type));
  }
  return absl::OkStatus();
}

// Reads |asn1| as a TCB ASN.1 value into |tcb| and |cpu_svn|.
Status ReadTcb(const Asn1Value &asn1, Tcb *tcb, CpuSvn *cpu_svn) {
  absl::flat_hash_map<ObjectId, ReadInfo> read_functions(
      {{GetSgxOids().pce_svn,
        {[tcb](const Asn1Value &asn1) -> Status {
           uint16_t pce_svn;
           ASYLO_ASSIGN_OR_RETURN(pce_svn, asn1.GetIntegerAsInt<uint16_t>());
           tcb->mutable_pce_svn()->set_value(pce_svn);
           return absl::OkStatus();
         },
         Optionality::REQUIRED}},
       {GetSgxOids().cpu_svn,
        {[cpu_svn](const Asn1Value &asn1) -> Status {
           std::vector<uint8_t> cpu_svn_bytes;
           ASYLO_ASSIGN_OR_RETURN(cpu_svn_bytes,
                                  ReadOctetStringWithSize(asn1, kCpusvnSize));
           cpu_svn->set_value(cpu_svn_bytes.data(), cpu_svn_bytes.size());
           return absl::OkStatus();
         },
         Optionality::REQUIRED}}});
  ObjectId oid;
  for (int i = 0; i < kTcbComponentsSize; ++i) {
    read_functions.insert({GetSgxOids().sgx_tcb_comp_svns[i],
                           {[tcb, i](const Asn1Value &asn1) -> Status {
                              // Read as a uint8_t and cast to disallow negative
                              // values.
                              uint8_t component;
                              ASYLO_ASSIGN_OR_RETURN(
                                  component, asn1.GetIntegerAsInt<uint8_t>());
                              (*tcb->mutable_components())[i] =
                                  *reinterpret_cast<char *>(&component);
                              return absl::OkStatus();
                            },
                            Optionality::REQUIRED}});
  }

  std::vector<std::tuple<ObjectId, Asn1Value>> sequence;
  ASYLO_ASSIGN_OR_RETURN(sequence, OidAnySequenceSchema().Read(asn1));
  // Ensure that tcb.components has a slot for each TCB component.
  tcb->mutable_components()->resize(kTcbComponentsSize);
  return ReadOidAnySequence(read_functions, sequence);
}

// Writes |tcb| and |cpu_svn| to a TCB ASN.1 value.
StatusOr<Asn1Value> WriteTcb(const Tcb &tcb, const CpuSvn &cpu_svn) {
  std::vector<std::tuple<ObjectId, Asn1Value>> sequence;
  Asn1Value asn1;
  for (int i = 0; i < kTcbComponentsSize; ++i) {
    // Use Asn1Value::CreateIntegerFromInt<uint8_t> to avoid negative values.
    ASYLO_ASSIGN_OR_RETURN(
        asn1, Asn1Value::CreateIntegerFromInt<uint8_t>(
                  *reinterpret_cast<const uint8_t *>(&tcb.components()[i])));
    sequence.push_back({GetSgxOids().sgx_tcb_comp_svns[i], asn1});
  }
  ASYLO_ASSIGN_OR_RETURN(
      asn1, Asn1Value::CreateIntegerFromInt<uint16_t>(tcb.pce_svn().value()));
  sequence.push_back({GetSgxOids().pce_svn, asn1});
  ASYLO_ASSIGN_OR_RETURN(asn1, Asn1Value::CreateOctetString(cpu_svn.value()));
  sequence.push_back({GetSgxOids().cpu_svn, asn1});
  return OidAnySequenceSchema().Write(sequence);
}

// Validates a PckCertificates.PckCertificateInfo message.
Status ValidatePckCertificateInfo(
    const PckCertificates::PckCertificateInfo &cert_info) {
  if (!cert_info.has_tcb_level()) {
    return absl::InvalidArgumentError(
        "PckCertificateInfo does not have a \"tcb_level\" field");
  }
  if (!cert_info.has_tcbm()) {
    return absl::InvalidArgumentError(
        "PckCertificateInfo does not have a \"tcbm\" field");
  }
  if (!cert_info.has_cert()) {
    return absl::InvalidArgumentError(
        "PckCertificateInfo does not have a \"cert\" field");
  }

  ASYLO_RETURN_IF_ERROR(ValidateTcb(cert_info.tcb_level()));
  ASYLO_RETURN_IF_ERROR(ValidateRawTcb(cert_info.tcbm()));
  ASYLO_RETURN_IF_ERROR(ValidateCertificate(cert_info.cert()));

  if (!google::protobuf::util::MessageDifferencer::Equals(cert_info.tcb_level().pce_svn(),
                                                cert_info.tcbm().pce_svn())) {
    return absl::InvalidArgumentError(
        "PckCertificateInfo has two different PCE SVNs");
  }

  return absl::OkStatus();
}

}  // namespace

const ObjectId &GetSgxExtensionsOid() { return GetSgxOids().sgx_extensions; }

StatusOr<SgxExtensions> ReadSgxExtensions(const Asn1Value &extensions_asn1) {
  std::vector<std::tuple<ObjectId, Asn1Value>> sequence;
  ASYLO_ASSIGN_OR_RETURN(sequence,
                         OidAnySequenceSchema().Read(extensions_asn1));
  SgxExtensions extensions;
  absl::flat_hash_set<ObjectId> sequence_oids;
  ASYLO_RETURN_IF_ERROR(ReadOidAnySequence(
      {{GetSgxOids().ppid,
        {[&extensions](const Asn1Value &asn1) -> Status {
           std::vector<uint8_t> ppid_bytes;
           ASYLO_ASSIGN_OR_RETURN(ppid_bytes,
                                  ReadOctetStringWithSize(asn1, kPpidSize));
           extensions.ppid.set_value(ppid_bytes.data(), ppid_bytes.size());
           return absl::OkStatus();
         },
         Optionality::REQUIRED}},
       {GetSgxOids().tcb,
        {[&extensions](const Asn1Value &asn1) -> Status {
           return ReadTcb(asn1, &extensions.tcb, &extensions.cpu_svn);
         },
         Optionality::REQUIRED}},
       {GetSgxOids().pce_id,
        {[&extensions](const Asn1Value &asn1) -> Status {
           std::vector<uint8_t> pce_id_bytes;
           ASYLO_ASSIGN_OR_RETURN(
               pce_id_bytes, ReadOctetStringWithSize(asn1, sizeof(uint16_t)));
           extensions.pce_id.set_value(
               le16toh(*reinterpret_cast<uint16_t *>(pce_id_bytes.data())));
           return absl::OkStatus();
         },
         Optionality::REQUIRED}},
       {GetSgxOids().fmspc,
        {[&extensions](const Asn1Value &asn1) -> Status {
           std::vector<uint8_t> fmspc_bytes;
           ASYLO_ASSIGN_OR_RETURN(fmspc_bytes,
                                  ReadOctetStringWithSize(asn1, kFmspcSize));
           extensions.fmspc.set_value(fmspc_bytes.data(), fmspc_bytes.size());
           return absl::OkStatus();
         },
         Optionality::REQUIRED}},
       {GetSgxOids().sgx_type,
        {[&extensions](const Asn1Value &asn1) -> Status {
           using UnderlyingType = std::underlying_type<SgxTypeRaw>::type;
           UnderlyingType raw;
           ASYLO_ASSIGN_OR_RETURN(raw,
                                  asn1.GetEnumeratedAsInt<UnderlyingType>());
           ASYLO_ASSIGN_OR_RETURN(extensions.sgx_type, FromRawSgxType(raw));
           return absl::OkStatus();
         },
      Optionality::REQUIRED}}},
      sequence));
  return extensions;
}

StatusOr<Asn1Value> WriteSgxExtensions(const SgxExtensions &extensions) {
  ASYLO_RETURN_IF_ERROR(ValidateSgxExtensions(extensions));
  uint16_t pce_id_little_endian = htole16(extensions.pce_id.value());
  SgxTypeRaw enumerated_value;
  ASYLO_ASSIGN_OR_RETURN(enumerated_value, ToRawSgxType(extensions.sgx_type));

  std::vector<std::tuple<ObjectId, Asn1Value>> sequence;
  Asn1Value asn1;
  ASYLO_ASSIGN_OR_RETURN(asn1,
                         Asn1Value::CreateOctetString(extensions.ppid.value()));
  sequence.push_back({GetSgxOids().ppid, asn1});
  ASYLO_ASSIGN_OR_RETURN(asn1, WriteTcb(extensions.tcb, extensions.cpu_svn));
  sequence.push_back({GetSgxOids().tcb, asn1});
  ASYLO_ASSIGN_OR_RETURN(
      asn1, Asn1Value::CreateOctetString(ByteContainerView(
                &pce_id_little_endian, sizeof(pce_id_little_endian))));
  sequence.push_back({GetSgxOids().pce_id, asn1});
  ASYLO_ASSIGN_OR_RETURN(
      asn1, Asn1Value::CreateOctetString(extensions.fmspc.value()));
  sequence.push_back({GetSgxOids().fmspc, asn1});
  ASYLO_ASSIGN_OR_RETURN(
      asn1, Asn1Value::CreateEnumeratedFromInt(
                static_cast<std::underlying_type<SgxTypeRaw>::type>(
                    enumerated_value)));
  sequence.push_back({GetSgxOids().sgx_type, asn1});
  return OidAnySequenceSchema().Write(sequence);
}

Status ValidatePckCertificates(const PckCertificates &pck_certificates) {
  absl::flat_hash_map<Tcb, const PckCertificates::PckCertificateInfo *,
                      absl::Hash<Tcb>, MessageEqual>
      tcbs_to_certs;
  absl::flat_hash_set<RawTcb, absl::Hash<RawTcb>, MessageEqual> tcbms;
  for (const auto &cert_info : pck_certificates.certs()) {
    ASYLO_RETURN_IF_ERROR(ValidatePckCertificateInfo(cert_info));

    auto it = tcbs_to_certs.find(cert_info.tcb_level());
    if (it != tcbs_to_certs.end()) {
      if (!google::protobuf::util::MessageDifferencer::Equals(*it->second, cert_info)) {
        return absl::InvalidArgumentError(
            "PckCertificates contains two distinct entries with identical "
            "TCBs");
      } else {
        continue;
      }
    }

    if (tcbms.contains(cert_info.tcbm())) {
      return absl::InvalidArgumentError(
          "PckCertificates contains two distinct entries with identical TCBMs");
    }

    tcbs_to_certs.emplace(cert_info.tcb_level(), &cert_info);
    tcbms.insert(cert_info.tcbm());
  }

  return absl::OkStatus();
}

StatusOr<SgxExtensions> ExtractSgxExtensionsFromPckCert(
    const CertificateInterface &pck_certificate) {
  const X509Certificate *pck_cert =
      dynamic_cast<const X509Certificate *>(&pck_certificate);
  if (pck_cert == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "PCK certificate is not an X.509 certificate");
  }

  std::vector<X509Extension> pck_extensions;
  ASYLO_ASSIGN_OR_RETURN(
      pck_extensions,
      WithContext(pck_cert->GetOtherExtensions(),
                  "PCK certificate does not contain extensions"));
  for (const X509Extension &extension : pck_extensions) {
    if (extension.oid == GetSgxExtensionsOid()) {
      return ReadSgxExtensions(extension.value);
    }
  }

  return Status(absl::StatusCode::kInvalidArgument,
                "PCK certificate does not contain SGX extensions");
}

StatusOr<MachineConfiguration> ExtractMachineConfigurationFromPckCert(
    const CertificateInterface *pck_certificate) {
  SgxExtensions sgx_extensions;
  ASYLO_ASSIGN_OR_RETURN(sgx_extensions,
                         ExtractSgxExtensionsFromPckCert(*pck_certificate));

  MachineConfiguration machine_config;
  *machine_config.mutable_cpu_svn() = std::move(sgx_extensions.cpu_svn);
  machine_config.set_sgx_type(sgx_extensions.sgx_type);

  return machine_config;
}

StatusOr<CpuSvn> ExtractCpuSvnFromPckCert(const Certificate &pck_certificate) {
  std::unique_ptr<X509Certificate> pck_cert;
  ASYLO_ASSIGN_OR_RETURN(pck_cert, X509Certificate::Create(pck_certificate));

  SgxExtensions sgx_extensions;
  ASYLO_ASSIGN_OR_RETURN(sgx_extensions,
                         ExtractSgxExtensionsFromPckCert(*pck_cert));

  return sgx_extensions.cpu_svn;
}

StatusOr<PceSvn> ExtractPceSvnFromPckCert(const Certificate &pck_certificate) {
  std::unique_ptr<X509Certificate> pck_cert;
  ASYLO_ASSIGN_OR_RETURN(pck_cert, X509Certificate::Create(pck_certificate));

  SgxExtensions sgx_extensions;
  ASYLO_ASSIGN_OR_RETURN(sgx_extensions,
                         ExtractSgxExtensionsFromPckCert(*pck_cert));

  return sgx_extensions.tcb.pce_svn();
}

}  // namespace sgx
}  // namespace asylo
