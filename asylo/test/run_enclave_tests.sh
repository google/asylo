#!/bin/bash

BAZEL="bazel"

# Query for all of the tests marked as regression tests.
ASYLO_TESTS="tests(//asylo/...)"
NOREGRESSION_TESTS="attr(tags, noregression, ${ASYLO_TESTS})"
REGRESSION_TESTS=(
  $(${BAZEL} query "${ASYLO_TESTS} except ${NOREGRESSION_TESTS}")
)

# Separately run the host and enclave tests, with different configs.
# The "enclave_test" tag can be used to separate them, and "build_tests_only"
# has it only build that filtered set of tests instead of all provided targets.
${BAZEL} test --test_tag_filters=-enclave_test --build_tests_only \
  --define=GRPC_PORT_ISOLATED_RUNTIME=1 \
  "${REGRESSION_TESTS[@]}"
STAT=$?

${BAZEL} test --test_tag_filters=+enclave_test --build_tests_only \
  --define=GRPC_PORT_ISOLATED_RUNTIME=1 \
  --config=enc-sim "${REGRESSION_TESTS[@]}"
STAT=$((${STAT} || $?))

exit ${STAT}
