#!/bin/bash

BAZEL="bazel"

# Query for all of the tests marked as regression tests excluding tests in
# platform/primitives.
ASYLO_TESTS="tests(//asylo/...)"
ASYLO_SGX_TESTS="attr(tags, \"asylo-sgx\", tests(//asylo/...))"
ASYLO_SIM_TESTS="attr(tags, \"asylo-sim\", tests(//asylo/...))"
ASYLO_PRIMITIVES="tests(//asylo/platform/primitives/...)"
NOREGRESSION_TESTS="attr(tags, noregression, ${ASYLO_TESTS})"
HOST_REGRESSION_TESTS=($(${BAZEL} query "${ASYLO_TESTS} except
  ${NOREGRESSION_TESTS}")
)
SGX_REGRESSION_TESTS=($(${BAZEL} query "${ASYLO_SGX_TESTS} except
  ${NOREGRESSION_TESTS}")
)
SIM_REGRESSION_TESTS=($(${BAZEL} query "${ASYLO_SIM_TESTS} except
  ${NOREGRESSION_TESTS}")
)

# Separately run the host and enclave tests, with different configs.
# The "enclave_test" tag can be used to separate them, and "build_tests_only"
# has it only build that filtered set of tests instead of all provided targets.
${BAZEL} test --test_tag_filters=-enclave_test --build_tests_only \
  --define=GRPC_PORT_ISOLATED_RUNTIME=1 \
  "${HOST_REGRESSION_TESTS[@]}"
STAT=$?

${BAZEL} test --test_tag_filters=+enclave_test --build_tests_only \
  --define=GRPC_PORT_ISOLATED_RUNTIME=1 \
  --config=enc-sim "${SGX_REGRESSION_TESTS[@]}"
STAT=$((${STAT} || $?))

${BAZEL} test --test_tag_filters=+enclave_test --build_tests_only \
  --define=GRPC_PORT_ISOLATED_RUNTIME=1 \
  --config=asylo --define=ASYLO_SIM=1 "${SIM_REGRESSION_TESTS[@]}"
STAT=$((${STAT} || $?))

exit ${STAT}
