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

set -eu

# The location of the objcopy binary.
OBJCOPY=$1

# The location of the ELF file containing the embedded "enclave".
ELF_FILE_LOCATION=$2

# The name of the enclave's section.
SECTION_NAME=$3

# The location of a file containing the expected contents of $SECTION_NAME in
# $ELF_FILE_LOCATION.
EXPECTED_CONTENTS_FILE=$4

RESULT=0

# Check that attempting to copy $SECTION_NAME fails. This is expected because
# $SECTION_NAME should not have ALLOC or LOAD set.
SHOULD_BE_EMPTY=$(mktemp)
"${OBJCOPY}" -O binary --only-section "${SECTION_NAME}" "${ELF_FILE_LOCATION}" \
    "${SHOULD_BE_EMPTY}"
if [[ -n $(cat "${SHOULD_BE_EMPTY}") ]]; then
  echo "${SECTION_NAME} has ALLOC or LOAD set" >&2
  RESULT=1
fi
rm "${SHOULD_BE_EMPTY}"

# Check that the contents of $SECTION_NAME equals $EXPECTED_CONTENTS_FILE.
#
# objcopy version 2.25 has a --dump-section option that streamlines this
# test, but a workaround is necessary for older versions of objcopy.
VERSION=$("${OBJCOPY}" --version | head -n1 | rev | cut -d' ' -f 1 | rev)
MAJOR=$(echo "${VERSION}" | cut -d. -f 1)
MINOR=$(echo "${VERSION}" | cut -d. -f 2)
ACTUAL_CONTENTS_FILE=$(mktemp /tmp/actual.XXXXXXXXXX)

if [[ "${MAJOR}" -ge "3" || ("${MAJOR}" -eq "2" && "${MINOR}" -ge "25") ]]; then
  "${OBJCOPY}" --dump-section "${SECTION_NAME}=${ACTUAL_CONTENTS_FILE}" \
      "${ELF_FILE_LOCATION}" /dev/null
else
  INTERMEDIATE_FILE=$(mktemp)
  "${OBJCOPY}" --set-section-flags "${SECTION_NAME}=alloc" \
      "${ELF_FILE_LOCATION}" "${INTERMEDIATE_FILE}"
  "${OBJCOPY}" -O binary --only-section "${SECTION_NAME}" \
      "${INTERMEDIATE_FILE}" "${ACTUAL_CONTENTS_FILE}"
  rm "${INTERMEDIATE_FILE}"
fi

# Since diff exits with status 1 on a non-empty diff, and since we set -e at the
# top of the file, the diff call would cause the test to abort (without a
# failure message) if the file contents are different. As such, the diff call is
# followed by ||:, which suppresses failures. As a result, if the diff call
# experiences an actual error, that too will be suppressed.
THE_DIFF=$(diff -N "${EXPECTED_CONTENTS_FILE}" "${ACTUAL_CONTENTS_FILE}" ||:)
if [[ -n "${THE_DIFF}" ]]; then
  echo "Wrong contents of ${SECTION_NAME}:" >&2
  echo "${THE_DIFF}" >&2
  RESULT=1
fi
rm "${ACTUAL_CONTENTS_FILE}"

exit "${RESULT}"
