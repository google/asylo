/*
 *
 * Copyright 2018 Asylo authors
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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <memory>
#include <string>

#include <google/protobuf/io/zero_copy_stream_impl.h>
#include <google/protobuf/text_format.h>
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "asylo/crypto/util/trivial_object_util.h"
#include "asylo/util/logging.h"
#include "asylo/identity/platform/sgx/code_identity.pb.h"
#include "asylo/identity/platform/sgx/internal/fake_enclave.h"
#include "asylo/identity/platform/sgx/internal/identity_key_management_structs.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/sealing/sgx/internal/local_secret_sealer_test_data.pb.h"
#include "asylo/identity/sealing/sgx/sgx_local_secret_sealer.h"
#include "asylo/util/posix_errors.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"

ABSL_FLAG(std::string, infile, "",
          "Path to input file. No input file is opened if empty.");
ABSL_FLAG(std::string, outfile, "",
          "Path to output file. Writes to STDOUT if empty.");
ABSL_FLAG(uint64_t, change_id, 0, "Change id from which this tool was built.");
ABSL_FLAG(int32_t, plaintext_word_count, 10,
          "Length of plaintext to generate.");
ABSL_FLAG(int32_t, aad_word_count, 10,
          "Length of additional associated data to generate.");

namespace asylo {
namespace sgx {
namespace {

// Dictionary of words from which random strings are generated. Number of words
// in the dictionary must be an integer power of two between 1 and 256.
constexpr const char *kDictionary[16] = {
    "cows", "moo", "horses", "neigh", "dogs", "bark",  "cats", "meow",
    "why",  "are", "there",  "so",    "many", "words", "for",  "sounds",
};

// Returns a random word from the dictionary with uniform distribution.
std::string GetRandomWord() {
  return kDictionary[TrivialRandomObject<uint8_t>() %
                     (sizeof(kDictionary) / sizeof(kDictionary[0]))];
}

// Generates random text comprising |word_count| uniformly-selected words from
// the dictionary. Words may repeat.
std::string GenerateRandomText(size_t word_count) {
  std::string output = GetRandomWord();
  for (size_t i = 1; i < word_count; i++) {
    absl::StrAppend(&output, " ", GetRandomWord());
  }

  return output;
}

// Sets the thread-local fake-enclave identity to a random value.
void SetRandomEnclaveIdentity() {
  if (FakeEnclave::GetCurrentEnclave()) {
    FakeEnclave::ExitEnclave();
  }
  FakeEnclave enclave;
  enclave.SetRandomIdentity();

  // Set a random enclave CPUSVN to help distinguish between an unsealed secret
  // whose CPUSVN was errantly zeroed from an unsealed secret whose CPUSVN is
  // legitimately all zeroes at deserialization-time.
  enclave.set_cpusvn(TrivialRandomObject<UnsafeBytes<kCpusvnSize>>());
  FakeEnclave::EnterEnclave(enclave);
}

// Reads existing test data from the file pointed to by |input_path| and
// populates |test_data| accordingly. |input_path| is expected to hold a
// LocalSealedSecretTestData proto in text format.
Status ReadTestData(const std::string &input_path,
                    LocalSecretSealerTestData *test_data) {
  int fd = open(input_path.c_str(), O_RDONLY);
  if (fd < 0) {
    return LastPosixError(
        absl::StrCat("Could not open ", input_path, " for reading"));
  }
  google::protobuf::io::FileInputStream stream(fd);
  stream.SetCloseOnDelete(true);
  if (!google::protobuf::TextFormat::Parse(&stream, test_data)) {
    return absl::InternalError(absl::StrCat("Could not parse ", input_path));
  }
  return absl::OkStatus();
}

// Uses |sealer| to generate new test-data record for a random enclave identity
// and writes the resulting record to |record|.
Status SetTestDataRecord(std::unique_ptr<SgxLocalSecretSealer> sealer,
                         uint64_t change_id, size_t plaintext_word_count,
                         size_t aad_word_count, TestDataRecord *record) {
  // Set the record header.
  record->mutable_header()->set_creation_time(absl::FormatTime(absl::Now()));
  record->mutable_header()->set_change_id(change_id);
  record->mutable_header()->set_enclave_type(
      TestDataRecordHeader::FAKE_ENCLAVE);
  *record->mutable_header()->mutable_sgx_identity() = GetSelfSgxIdentity();

  // Set the sealed-secret header.
  SealedSecretHeader header;
  ASYLO_RETURN_IF_ERROR(sealer->SetDefaultHeader(&header));
  header.set_secret_name(
      absl::StrCat("secret ", TrivialRandomObject<uint64_t>()));
  header.set_secret_version(
      absl::StrCat("version ", TrivialRandomObject<uint64_t>()));
  header.set_secret_purpose("test");
  header.set_secret_handling_policy("none");

  // Generate the secret and the authenticated data. Write the plaintext to the
  // record.
  record->set_plaintext(GenerateRandomText(plaintext_word_count));
  std::string aad = GenerateRandomText(aad_word_count);

  // Seal the secret and write it to the record.
  return sealer->Seal(header, aad, record->plaintext(),
                      record->mutable_sealed_secret());
}

// Generates a new test-data record for each configuration supported by
// LocalSecretSealer, and appends each record to |test_data|->records(). The
// configurations supported by LocalSecretSealer are:
//   * Secrets bound to MRENCLAVE
//   * Secrets bound to MRSIGNER
Status AddToTestData(uint64_t change_id, size_t plaintext_word_count,
                     size_t aad_word_count,
                     LocalSecretSealerTestData *test_data) {
  // Set a random enclave identity.
  SetRandomEnclaveIdentity();

  ASYLO_RETURN_IF_ERROR(SetTestDataRecord(
      SgxLocalSecretSealer::CreateMrenclaveSecretSealer(), change_id,
      plaintext_word_count, aad_word_count, test_data->add_records()));

  // Change enclave identity.
  SetRandomEnclaveIdentity();
  ASYLO_RETURN_IF_ERROR(SetTestDataRecord(
      SgxLocalSecretSealer::CreateMrsignerSecretSealer(), change_id,
      plaintext_word_count, aad_word_count, test_data->add_records()));

  return absl::OkStatus();
}

// Writes |test_data| to the file pointed to by |output_path| in text format.
Status WriteTestData(const LocalSecretSealerTestData &test_data,
                     const std::string &output_path) {
  int fd;
  if (output_path.empty()) {
    // Write to STDOUT.
    fd = STDOUT_FILENO;
  } else {
    fd = open(output_path.c_str(), O_CREAT | O_WRONLY | O_TRUNC,
              S_IRUSR | S_IWUSR);
    if (fd < 0) {
      return LastPosixError(
          absl::StrCat("Could not open ", output_path, " for writing"));
    }
  }
  google::protobuf::io::FileOutputStream stream(fd);
  if (!output_path.empty()) {
    stream.SetCloseOnDelete(true);
  }
  if (!google::protobuf::TextFormat::Print(test_data, &stream)) {
    return absl::InternalError(
        absl::StrCat("Error while writing to ", output_path));
  }
  return absl::OkStatus();
}

}  // namespace
}  // namespace sgx
}  // namespace asylo

int main(int argc, char *argv[]) {
  absl::ParseCommandLine(argc, argv);

  LOG_IF(QFATAL, absl::GetFlag(FLAGS_change_id) == 0)
      << "Must specify non-zero --change_id";
  LOG_IF(QFATAL, absl::GetFlag(FLAGS_plaintext_word_count) < 1)
      << "--plaintext_word_count must be greater than zero";
  LOG_IF(QFATAL, absl::GetFlag(FLAGS_aad_word_count) < 1)
      << "--aad_word_count must be greater than zero";

  asylo::sgx::LocalSecretSealerTestData test_data;
  asylo::Status status;

  if (!absl::GetFlag(FLAGS_infile).empty()) {
    status = asylo::sgx::ReadTestData(absl::GetFlag(FLAGS_infile), &test_data);
    LOG_IF(QFATAL, !status.ok()) << status;
  }

  status = asylo::sgx::AddToTestData(
      absl::GetFlag(FLAGS_change_id),
      static_cast<size_t>(absl::GetFlag(FLAGS_plaintext_word_count)),
      static_cast<size_t>(absl::GetFlag(FLAGS_aad_word_count)), &test_data);
  LOG_IF(QFATAL, !status.ok()) << status;

  status = asylo::sgx::WriteTestData(test_data, absl::GetFlag(FLAGS_outfile));
  LOG_IF(QFATAL, !status.ok()) << status;

  return 0;
}
