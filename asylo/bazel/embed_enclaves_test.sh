#!/bin/bash
#
# Copyright 2018 Asylo authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

source asylo/test/util/shell_testing.sh

set -u

# The location of the objcopy binary.
OBJCOPY=$1

# The location of the ELF file containing the embedded "enclave".
ELF_FILE_LOCATION=$2

# The name of the enclave's section.
SECTION_NAME=$3

# The location of a file containing the expected contents of $SECTION_NAME in
# $ELF_FILE_LOCATION.
EXPECTED_CONTENTS_FILE=$4

# Check that attempting to copy $SECTION_NAME fails. This is expected because
# $SECTION_NAME should not have ALLOC or LOAD set.
function test::embedded_section_does_not_have_alloc_or_load() {
  SHOULD_BE_EMPTY=$(mktemp)
  "${OBJCOPY}" -O binary --only-section "${SECTION_NAME}" \
      "${ELF_FILE_LOCATION}" "${SHOULD_BE_EMPTY}"
  expect_str_eq "$(cat "${SHOULD_BE_EMPTY}")" ""
  rm "${SHOULD_BE_EMPTY}"
}

# Check that the contents of $SECTION_NAME equals $EXPECTED_CONTENTS_FILE.
#
# objcopy version 2.25 has a --dump-section option that streamlines this
# test, but a workaround is necessary for older versions of objcopy.
function test::section_contents_equals_expected_file() {
  VERSION_HEADER=$("${OBJCOPY}" --version | head -n1)
  GNU_VERSION=$(echo "${VERSION_HEADER}" | rev | cut -d' ' -f 1 | rev)
  GNU_MAJOR=$(echo "${GNU_VERSION}" | cut -d. -f 1)
  GNU_MINOR=$(echo "${GNU_VERSION}" | cut -d. -f 2)
  ACTUAL_CONTENTS_FILE=$(mktemp /tmp/actual.XXXXXXXXXX)

  if [[ "${VERSION_HEADER,,}" == *llvm* || "${GNU_MAJOR}" -ge "3" ||
          ("${GNU_MAJOR}" -eq "2" && "${GNU_MINOR}" -ge "25") ]]; then
    "${OBJCOPY}" --dump-section "${SECTION_NAME}=${ACTUAL_CONTENTS_FILE}" \
        "${ELF_FILE_LOCATION}" /dev/null
  else
    "${OBJCOPY}" -O binary --only-section "${SECTION_NAME}" \
        --set-section-flags "${SECTION_NAME}=alloc" \
        "${ELF_FILE_LOCATION}" "${ACTUAL_CONTENTS_FILE}"
  fi

  # Since diff exits with status 1 on a non-empty diff, and since we set -e at
  # the top of the file, the diff call would cause the test to abort (without a
  # failure message) if the file contents are different. As such, the diff call
  # is followed by ||:, which suppresses failures. As a result, if the diff call
  # experiences an actual error, that too will be suppressed.
  expect_regular_file "${EXPECTED_CONTENTS_FILE}"
  expect_regular_file "${ACTUAL_CONTENTS_FILE}"
  THE_DIFF=$(diff -N "${EXPECTED_CONTENTS_FILE}" "${ACTUAL_CONTENTS_FILE}" ||:)
  expect_str_eq "${THE_DIFF}" ""
  rm "${ACTUAL_CONTENTS_FILE}"
}

test_main
