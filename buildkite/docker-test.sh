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

# This script uses Asylo docker container to run Asylo tests.
# It assumes that the host machine has SGX installed and enabled
# as described here:
# https://github.com/google/asylo/blob/master/INSTALL.md#intel-sgx-sdk

ensure() {
  if [[ -z "$1" ]]; then
    [[ -z "$2" ]] || echo "ERROR: $2"
    exit 1
  fi
}

ensure "${ASYLO_SDK}" "ASYLO_SDK is not defined!"
ensure "${BUILDKITE_BUILD_ID}" "BUILDKITE_BUILD_ID is not defined!"
ensure "${BUILDKITE_STEP_ID}" "BUILDKITE_STEP_ID is not defined!"

STAT=0
RED='\e[1;31m'
GREEN='\e[1;32m'
RESET='\e[0m'

# Asylo Build Flags
BUILD_EVENT_FILE="/home/${USER}/build_events.json"
ASYLO_EXTRA_BAZEL_FLAGS="build --noshow_progress --verbose_failures \
--announce_rc --test_output=summary --test_summary=short \
--color=yes --build_event_json_file=\"${BUILD_EVENT_FILE}\""

: "${ASYLO_BUILD_ROOT:=/var/tmp/asylo-build}"
# We check that ${ASYLO_BUILD_ROOT} is already writable by ${USER}.
if [ -w "${ASYLO_BUILD_ROOT}" ]; then
  echo "${ASYLO_BUILD_ROOT} is writable. Proceeding;"
else
  echo "ERROR: ${ASYLO_BUILD_ROOT} is not writable or does not exist!"
  exit 1
fi

# Create build dir
mkdir -p "${ASYLO_BUILD_ROOT}/${BUILDKITE_BUILD_ID}"
mkdir -p "${ASYLO_BUILD_ROOT}/${BUILDKITE_BUILD_ID}/${BUILDKITE_STEP_ID}"
# We will collect build artifacts here
mkdir -p "${ASYLO_BUILD_ROOT}/${BUILDKITE_BUILD_ID}/${BUILDKITE_STEP_ID}/artifacts/"

# Support for IPv6 build agents
: "${ASYLO_BUILD_IPV6:=1}"
if [[ ${ASYLO_BUILD_IPV6} -eq 1 ]];
then
  echo "Bazel will be configured to prefer IPv6"
  PREFER_IPV6="-Djava.net.preferIPv6Addresses=true"
  ASYLO_EXTRA_BAZEL_FLAGS+=$'\n'"startup --host_jvm_args=${PREFER_IPV6}"
  ASYLO_EXTRA_BAZEL_FLAGS+=$'\n'"build --jvmopt=${PREFER_IPV6}"
  COURSIER_OPTS="${PREFER_IPV6}"
fi

# Generate random container name
CONTAINER_NAME=asylo${RANDOM}

echo "--- :docker: Starting Docker Container ${CONTAINER_NAME}"

# If SGX is present, we'll pass it into the container
# so it can use it if it wants.
# Note that we MUST have SGX when ${ASYLO_TO_TEST}==sgx
SGX_HW_ARGS=()
if [ -c /dev/isgx ] && [ -S /var/run/aesmd/aesm.socket ]; then
  echo "SGX device has been detected and will be passed to docker."
  SGX_HW_ARGS+=("--device=/dev/isgx")
  SGX_HW_ARGS+=("--volume=/var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket")
else
  echo "SGX has not been detected."
  if [[ " ${ASYLO_TO_TEST} " =~ --sgx[^-] ]];
  then
    echo "WARNING: You are running tests that require SGX hardware," \
    "they will fail without SGX."
  fi
fi

# Pull the latest Asylo image
: "${ASYLO_DOCKER_IMAGE:=gcr.io/asylo-framework/asylo}"
docker pull ${ASYLO_DOCKER_IMAGE}

# Start Asylo Docker Container
# Note how we map home directory for the user to tmpfs to speed up build time.
# We also mount /artifacts volume so that we can copy files we want to preserve.
docker run \
    --env ASYLO_EXTRA_BAZEL_FLAGS="${ASYLO_EXTRA_BAZEL_FLAGS}" \
    --env COURSIER_OPTS="${COURSIER_OPTS}" \
    --volume "${ASYLO_SDK}:/opt/asylo/sdk" \
    --volume "${ASYLO_BUILD_ROOT}/${BUILDKITE_BUILD_ID}/${BUILDKITE_STEP_ID}/artifacts:/artifacts" \
    "${SGX_HW_ARGS[@]}" \
    --tmpfs "/home/${USER}:exec" \
    -w "/opt/asylo/sdk" \
    -it \
    --rm \
    --name ${CONTAINER_NAME} \
    --detach \
    ${ASYLO_DOCKER_IMAGE}

# Stop container on EXIT or on SIGNIT no matter what happens
trap 'docker stop ${CONTAINER_NAME} >/dev/null' EXIT SIGINT

# Run future commands in the container we just created.
# ${DOCKER_ROOT} runs the command as root in the container, and should be used
# for commands that require root (i.e., apt-get).
# ${DOCKER} runs the command as an unprivileged user, and any files it creates
# on the host will be owned by the runner of the script.
DOCKER_ROOT="docker exec -i ${CONTAINER_NAME}"
DOCKER="docker exec -i \
  --user $(id -u):$(id -g) \
  --env USER=${USER} \
  --env HOME=/home/${USER} \
  ${CONTAINER_NAME}"

# Create a user in the container to match the user running the script.
# Parts of Bazel get unhappy if running as a user id that isn't registered.
${DOCKER_ROOT} useradd -u "$(id -u)" "${USER}"

# Remove output files
echo "--- :bazel: Cleaning previous artifacts, if any"
${DOCKER} bazel clean

# Run Tests
echo "--- :gear: Running Tests ${ASYLO_TO_TEST}"
${DOCKER} asylo/test/run_enclave_tests.sh "${ASYLO_TO_TEST}"
STAT=$((STAT || $?))

# Now test results are in bazel cache and Build Event files are in /home/${USER}.
# We use artifacts collection script to copy test logs and test xml results
# from tmpfs (where they will be lost once container stops)
# to /artifacts which has been mounted to a physical location on the host
# ${ASYLO_BUILD_ROOT}/${BUILDKITE_BUILD_ID}/${BUILDKITE_STEP_ID}/artifacts.
# Our intent to use them as BuildKite artifacts
# (see https://buildkite.com/docs/pipelines/artifacts)
echo "--- :package: Collecting Test Artifacts"
${DOCKER} python3 buildkite/collect_artifacts.py \
            --build-events="${BUILD_EVENT_FILE}" \
            --destination=/artifacts

# Uploading Test Artifacts to Buildkite
if [ -x "$(command -v buildkite-agent)" ]; then
  echo "--- :package: Uploading Build Artifacts"
  cd "${ASYLO_BUILD_ROOT}/${BUILDKITE_BUILD_ID}/${BUILDKITE_STEP_ID}/artifacts"\
  || exit 1
  buildkite-agent artifact upload ./**/*.*
fi

# General cleanup: We don't want to run out of disc space
echo "--- :wastebasket: Cleaning up older build dirs"
find ${ASYLO_BUILD_ROOT}/* -type d -ctime +14 -exec rm -rf {} \;

if [[ ${STAT} -eq 0 ]]; then
  echo -e "${GREEN}BUILD SUCCESSFUL${RESET}"
else
  echo -e "${RED}BUILD FAILED${RESET}"
fi
exit ${STAT}

# Container will be stopped by trap above, no need to stop it here
