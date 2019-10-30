#!/bin/bash

# Set up cleanup hook for when script exits.
CLEANUP_FUNCS=()
cleanup() {
  for func in "${CLEANUP_FUNCS[@]}"; do
    ${func}
  done
}
trap cleanup EXIT

# Allow the caller to provide additional Bazel flags.
BAZELRC="$(mktemp)"
cat > "${BAZELRC}" <<< "${ASYLO_EXTRA_BAZEL_FLAGS}"
BAZEL="bazel --bazelrc=${BAZELRC}"
delete_bazelrc() { rm "${BAZELRC}"; }
CLEANUP_FUNCS+=(delete_bazelrc)

PKG="//asylo"

# Query for all of the tests marked as regression tests excluding tests in
# platform/primitives.
ASYLO_TESTS="tests(${PKG}/...)"
ASYLO_SGX_TESTS="attr(tags, \"asylo-sgx\", tests(${PKG}/...))"
ASYLO_DLOPEN_TESTS="attr(tags, \"asylo-dlopen\", tests(${PKG}/...))"
ENCLAVE_TESTS="attr(tags, \"enclave_test\", tests(${PKG}/...))"
ASYLO_PRIMITIVES="tests(${PKG}/platform/primitives/...)"
NOREGRESSION_TESTS="attr(tags, noregression, ${ASYLO_TESTS})"
HOST_REGRESSION_TESTS=($(${BAZEL} query "${ASYLO_TESTS} except
  ${NOREGRESSION_TESTS}")
)
SGX_REGRESSION_TESTS=($(${BAZEL} query "${ASYLO_SGX_TESTS} except
  ${NOREGRESSION_TESTS}")
)
DLOPEN_REGRESSION_TESTS=($(${BAZEL} query "${ASYLO_DLOPEN_TESTS} except
  ${NOREGRESSION_TESTS}")
)
UNTAGGED_TESTS=($(${BAZEL} query "${ENCLAVE_TESTS} except
  (${NOREGRESSION_TESTS} union ${ASYLO_DLOPEN_TESTS} union ${ASYLO_SGX_TESTS})"))

STAT=0
if [[ "${#UNTAGGED_TESTS[@]}" -ne 0 ]]; then
  STAT=1
  echo "ERROR: Tests without backend tags found:"
  echo "${UNTAGGED_TESTS[@]}"
fi

# Separately run the host and enclave tests, with different configs.
# The "enclave_test" tag can be used to separate them, and "build_tests_only"
# has it only build that filtered set of tests instead of all provided targets.
${BAZEL} test --test_tag_filters=-enclave_test --build_tests_only \
  "${HOST_REGRESSION_TESTS[@]}"
STAT=$(($STAT || $?))

${BAZEL} test --test_tag_filters=+enclave_test --build_tests_only \
  --config=sgx-sim "${SGX_REGRESSION_TESTS[@]}"
STAT=$((${STAT} || $?))

${BAZEL} test --test_tag_filters=+enclave_test --build_tests_only \
  --config=asylo --define=ASYLO_DLOPEN=1 "${DLOPEN_REGRESSION_TESTS[@]}"
STAT=$((${STAT} || $?))

RED='\e[1;31m'
GREEN='\e[1;32m'
RESET='\e[0m'

if [[ ${STAT} -eq 0 ]]; then
  echo -e "${GREEN}ALL TESTS PASSED${RESET}"
else
  echo -e "${RED}ONE OR MORE TESTS FAILED${RESET}"
fi
exit ${STAT}
