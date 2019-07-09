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

# A set of utilities for writing shell tests.
#
# To use this interface:
#   * Source shell_testing.sh at the beginning of your test script.
#   * Write each test as a function whose name begins with "test::".
#   * Call test_main at the end of your test script.

set -e

# A variable to hold the exit code to return from this test.
_ASYLO_TESTING_RETURN=0

# Runs all test::... functions, prints out a message indicating whether the
# tests passed, and exits.
function test_main() {
  _RETURN=0

  for test_function in $(declare -F | awk '$3 ~ /test::/ {print $3}'); do
    _ASYLO_TESTING_RETURN=0
    LOCAL_RETURN="$(eval "${test_function}"; echo "${_ASYLO_TESTING_RETURN}")"
    if [[ -z "${LOCAL_RETURN}" ]] || [[ "${LOCAL_RETURN}" -ne 0 ]]; then
      _RETURN=1
    fi
  done

  if [[ "${_RETURN}" -eq 0 ]]; then
    echo "Tests passed!"
  else
    echo "Tests failed!"
  fi

  exit "${_RETURN}"
}

# Checks that two strings are equal. If they are not, then the test will fail,
# but the test script will continue executing.
function expect_str_eq() {
  LHS=$1
  RHS=$2

  if [[ "${LHS}" != "${RHS}" ]]; then
    echo "FAILED: \"${LHS}\" does not equal \"${RHS}\"" >&2
    _ASYLO_TESTING_RETURN=1
  fi
}

# Checks that two integers are equal. If they are not, then the test will fail,
# but the test script will continue executing.
function expect_int_eq() {
  LHS=$1
  RHS=$2

  if [[ "${LHS}" -ne "${RHS}" ]]; then
    echo "FAILED: ${LHS} does not equal ${RHS}" >&2
    _ASYLO_TESTING_RETURN=1
  fi
}

# Checks that $1 exists and is a regular file. If it does not exist or exists
# but is not a regular file, then the test will fail, but the test script will
# continue executing.
function expect_regular_file() {
  FILEPATH=$1

  if [[ ! -e "${FILEPATH}" ]]; then
    echo "FAILED: ${FILEPATH} does not exist" >&2
    _ASYLO_TESTING_RETURN=1
  elif [[ ! -f "${FILEPATH}" ]]; then
    echo "FAILED: ${FILEPATH} is not a regular file" >&2
    _ASYLO_TESTING_RETURN=1
  fi
}

_ASYLO_LOCATION_DEBUG_TEXT="$(cat << EOF
  It looks like a \$\(location ...\) or \$\(locations ...\) expression failed to
  expand in Bazel.
EOF
)"

# A location function to provide users with a helpful debug message if a
# $(location ...) expression fails to expand.
function location() {
  echo "${_ASYLO_LOCATION_DEBUG_TEXT}" >&2
  echo "  Expression: location $@" >&2
  exit 1
}

# A location function to provide users with a helpful debug message if a
# $(locations ...) expression fails to expand.
function locations() {
  echo "${_ASYLO_LOCATION_DEBUG_TEXT}" >&2
  echo "  Expression: locations $@" >&2
  exit 1
}
