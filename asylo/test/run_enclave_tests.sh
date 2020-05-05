#!/bin/bash

# Allow the caller to provide additional Bazel flags.
BAZELRC="$(mktemp)"
cat > "${BAZELRC}" <<< "${ASYLO_EXTRA_BAZEL_FLAGS}"
BAZEL="${BAZEL:-bazel} --bazelrc=${BAZELRC}"
delete_bazelrc() { rm "${BAZELRC}"; }
trap delete_bazelrc EXIT

read -r -a TO_TEST <<< "${ASYLO_TO_TEST}"
readonly ALL_UNSPECIALIZED_TESTS=("host" "dlopen" "sgx-sim")
readonly SHORT="hdxX"
readonly LONG="host,dlopen,sgx,sgx-sim"
readonly PARSED=$(getopt -o "${SHORT}" --long "${LONG}" -n "${SELF}" -- "${@}")
eval set -- "${PARSED}"
while true; do
  case "$1" in
    -h|--host) TO_TEST+=("host"); shift ;;
    -d|--dlopen) TO_TEST+=("dlopen"); shift ;;
    -x|--sgx-sim) TO_TEST+=("sgx-sim"); shift ;;
    -X|--sgx) TO_TEST+=("sgx"); shift ;;
    --) shift ; break ;;
    *) error "Unexpected option $1" ;;
  esac
done

# If nothing added, then add all tests that don't require special hardware.
if [[ ${#TO_TEST[@]} -eq 0 ]]; then
  TO_TEST=("${ALL_UNSPECIALIZED_TESTS[@]}")
fi

# Make queries quieter.
echo "query --noshow_progress" >> "${BAZELRC}"

# Query for all of the tests marked as regression tests excluding tests in
# platform/primitives.
ASYLO_TESTS="tests(//asylo/...)"
ASYLO_SGX_HW_TESTS="attr(tags, \"asylo-sgx-hw\", tests(//asylo/...))"
ASYLO_SGX_SIM_TESTS="attr(tags, \"asylo-sgx-sim\", tests(//asylo/...))"
ASYLO_DLOPEN_TESTS="attr(tags, \"asylo-dlopen\", tests(//asylo/...))"
ASYLO_REMOTE_TESTS="attr(tags, \"asylo-remote\", tests(//asylo/...))"
ASYLO_PERF_TESTS="attr(tags, \"perf\", tests(//asylo/...))"
# Use the Bazel configuration transitions backend-switching strategy:
ASYLO_TRANSITION_TESTS="attr(tags, \"asylo-transition\", tests(//asylo/...))"
ENCLAVE_TESTS="attr(tags, \"enclave_test\", tests(//asylo/...))"

ASYLO_PRIMITIVES="tests(//asylo/platform/primitives/...)"
NOREGRESSION_TESTS="attr(tags, noregression, ${ASYLO_TESTS})"
IGNORE_TESTS="${NOREGRESSION_TESTS} union ${ASYLO_PERF_TESTS}"
HOST_REGRESSION_TESTS=($(${BAZEL} query "${ASYLO_TESTS} except
  (${IGNORE_TESTS} union ${ENCLAVE_TESTS})")
)
UNTAGGED_TESTS=($(${BAZEL} query "${ENCLAVE_TESTS} except
  (${IGNORE_TESTS} union ${ASYLO_DLOPEN_TESTS} union ${ASYLO_SGX_HW_TESTS} union ${ASYLO_SGX_SIM_TESTS})" \
  2> >(grep -v 'Empty results' >&2))) # Filter warning, since we expect empty.
SGX_HW_REGRESSION_TESTS=($(${BAZEL} query "(${ASYLO_SGX_HW_TESTS} except
  (${IGNORE_TESTS} union ${ASYLO_REMOTE_TESTS})) intersect ${ASYLO_TESTS}")
)
SGX_SIM_REGRESSION_TESTS=($(${BAZEL} query "(${ASYLO_SGX_SIM_TESTS} except
  (${IGNORE_TESTS} union ${ASYLO_REMOTE_TESTS})) intersect ${ASYLO_TESTS}")
)
DLOPEN_REGRESSION_TESTS=($(${BAZEL} query "(${ASYLO_DLOPEN_TESTS} except
  (${IGNORE_TESTS} union ${ASYLO_REMOTE_TESTS})) intersect ${ASYLO_TESTS}")
)

STAT=0
if [[ "${#UNTAGGED_TESTS[@]}" -ne 0 ]]; then
  STAT=1
  echo "ERROR: Tests without backend tags found:"
  echo "${UNTAGGED_TESTS[@]}"
fi

ALL_SELECTED_TESTS=()
if [[ " ${TO_TEST[@]} " =~ " host " ]]; then
  if [[ ${#HOST_REGRESSION_TESTS[@]} > 0 ]]; then
    echo "Host regression Tests Found:"
    printf "  %s\n" "${HOST_REGRESSION_TESTS[@]}" | sort
    ALL_SELECTED_TESTS+=("${HOST_REGRESSION_TESTS[@]}")
  else
    STAT=1
    echo "ERROR: Host tests specified, but none found"
  fi
fi
if [[ " ${TO_TEST[@]} " =~ " sgx " ]]; then
  if [[ ${#SGX_HW_REGRESSION_TESTS[@]} > 0 ]]; then
    echo "SGX hardware regression Tests Found:"
    printf "  %s\n" "${SGX_HW_REGRESSION_TESTS[@]}" | sort
    ALL_SELECTED_TESTS+=("${SGX_HW_REGRESSION_TESTS[@]}")
  else
    STAT=1
    echo "ERROR: SGX tests specified, but none found"
  fi
fi
if [[ " ${TO_TEST[@]} " =~ " sgx-sim " ]]; then
  if [[ ${#SGX_SIM_REGRESSION_TESTS[@]} > 0 ]]; then
    echo "SGX simulation regression Tests Found:"
    printf "  %s\n" "${SGX_SIM_REGRESSION_TESTS[@]}" | sort
    ALL_SELECTED_TESTS+=("${SGX_SIM_REGRESSION_TESTS[@]}")
  else
    STAT=1
    echo "ERROR: SGX sim tests specified, but none found"
  fi
fi
if [[ " ${TO_TEST[@]} " =~ " dlopen " ]]; then
  if [[ ${#DLOPEN_REGRESSION_TESTS[@]} > 0 ]]; then
    echo "Dlopen regression Tests Found:"
    printf "  %s\n" "${DLOPEN_REGRESSION_TESTS[@]}" | sort
    ALL_SELECTED_TESTS+=("${DLOPEN_REGRESSION_TESTS[@]}")
  else
    STAT=1
    echo "ERROR: Dlopen tests specified, but none found"
  fi
fi

if [[ ${#ALL_SELECTED_TESTS[@]} > 0 ]]; then
  # Now, actually run the tests
  ${BAZEL} test "${ALL_SELECTED_TESTS[@]}"
  STAT=$(($STAT || $?))
fi

RED='\e[1;31m'
GREEN='\e[1;32m'
RESET='\e[0m'

if [[ ${STAT} -eq 0 ]]; then
  echo -e "${GREEN}ALL TESTS PASSED${RESET}"
else
  echo -e "${RED}ONE OR MORE TESTS FAILED${RESET}"
fi
exit ${STAT}
