/*
 *
 * Copyright 2020 Asylo authors
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

#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_path_setter.h"

#include <libgen.h>

#include <unordered_set>

#include "absl/container/node_hash_set.h"
#include "absl/flags/flag.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "asylo/identity/attestation/sgx/internal/dcap_intel_architectural_enclave_interface.h"
#include "asylo/identity/attestation/sgx/internal/host_dcap_library_interface.h"
#include "asylo/util/error_codes.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"

ABSL_FLAG(std::string, intel_enclave_locations, "",
          "Runtime locations of the Intel PCE and QE binaries are located.");

namespace asylo {
namespace sgx {
namespace {

// Returns a single string that must be the shared parent directory of all the
// paths in `locations`, or fails.
StatusOr<std::string> DirPathFromLocations(absl::string_view locations) {
  absl::node_hash_set<std::string> parents;
  for (absl::string_view location : absl::StrSplit(locations, ' ')) {
    std::vector<char> location_copy(location.begin(), location.end());
    location_copy.push_back('\0');
    parents.insert(dirname(location_copy.data()));
  }
  if (parents.size() != 1) {
    return Status(absl::StatusCode::kInvalidArgument,
                  absl::StrCat("Expected a shared directory for all locations ",
                               locations));
  }
  return std::string(*parents.begin());
}

}  // namespace

Status SetIntelEnclaveDirFromFlags() {
  std::string locations = absl::GetFlag(FLAGS_intel_enclave_locations);
  if (locations.empty()) {
    return absl::OkStatus();
  }

  // The enclave path is global for all calls into the DCAP API.
  DcapIntelArchitecturalEnclaveInterface enclave_interface(
      absl::make_unique<HostDcapLibraryInterface>());
  std::string enclave_dirpath;
  ASYLO_ASSIGN_OR_RETURN(enclave_dirpath, DirPathFromLocations(locations));
  return enclave_interface.SetEnclaveDir(enclave_dirpath);
}

}  // namespace sgx
}  // namespace asylo
