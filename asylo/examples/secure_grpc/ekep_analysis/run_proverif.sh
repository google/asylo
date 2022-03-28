#!/bin/sh

# Copyright 2022 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

    # https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o pipefail
set -o nounset

if [[ "$#" != "1" ]]; then
  echo "Usage: $0 <file.pv>"
  exit 1
fi

readonly file="$1"
readonly TEMP_DIR="$(mktemp -d)"

function cleanup() {
  rm -rf "${TEMP_DIR}"
}

if [[ -z "${PROVERIF_NO_CLEANUP:-}" ]]; then
  trap cleanup EXIT
else
  echo "Output in ${TEMP_DIR}"
fi

if [[ -n "${PROVERIF_INTERACT:-}" ]]; then
  cpp -DENABLE_DEBUG_FUNCTIONS -E "${file}" \
    | grep -v "^#" > "${TEMP_DIR}/${file}"
else
  cpp -E "${file}" | grep -v "^#" > "${TEMP_DIR}/${file}"
fi

if [[ ! -z "${PROVERIF_INTERACT:-}" ]]; then
  proverif_interact "${TEMP_DIR}/${file}"
elif [[ ! -z "${PROVERIF_HTML_DIR:-}" ]]; then
  proverif -color -html "${PROVERIF_HTML_DIR}" "${TEMP_DIR}/${file}"
else
  proverif -color "${TEMP_DIR}/${file}"
fi
