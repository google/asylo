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

NORMAL_APPLICATION="asylo/bazel/application_wrapper/test_application"
ENCLAVE_APPLICATION="asylo/bazel/application_wrapper/test_enclave_application_sgx_sim"
ENCLAVE_LOADER="asylo/bazel/application_wrapper/test_enclave_application_host_loader"

# Command-line arguments to pass to the test applications.
TEST_ARGS="the quick brown fox jumps over the lazy dog"

# The command-line arguments, separated by newlines.
ARGS_BY_LINE="$(printf "the\nquick\nbrown\nfox\njumps\nover\nthe\nlazy\ndog\n")"

# The expected exit code of the applications. Equal to the number of
# command-line arguments above, plus one for argv[0].
EXPECTED_RETURN=10

# Test that the application at $1 prints each of its command-line arguments on a
# new line, in order.
#
# If $2 is specified, then its value is used instead of $1 for the expected
# value of the first command-line argument (argv[0]).
#
# If $3 is specified, then test_application also expects that $1 prints $3 after
# printing its command-line arguments. This should only be used for testing
# features of the application wrapper that are specific to enclaves.
function test_application() {
  APPLICATION=$1
  if [[ -n "$2" ]]; then
    APP_NAME=$2
  else
    APP_NAME="${APPLICATION}"
  fi

  EXPECTED_OUTPUT="$(printf "${APP_NAME}\n${ARGS_BY_LINE}\n$3")"

  set +e
  APP_OUTPUT="$($APPLICATION $TEST_ARGS)"
  APP_RETURN="$?"
  set -e

  expect_str_eq "${APP_OUTPUT}" "${EXPECTED_OUTPUT}"
  expect_int_eq "${APP_RETURN}" "${EXPECTED_RETURN}"
}

function test::normal_application_prints_command_line_args_and_environment_variables() {
  test_application "${NORMAL_APPLICATION}"
}

function test::enclave_application_prints_command_line_args_and_foo_variable() {
  test_application "${ENCLAVE_APPLICATION}" "./${ENCLAVE_LOADER}" \
    "$(printf 'FOO="foooo"\n')"
}

test_main
