#!/bin/bash
# Script for building the remote quickstart example.
#
# Instructions for use:
# Set environment variables ASYLO_SDK, MY_PROJECT, MESSAGE, and CONFIG_TYPE.
# -- ASYLO_SDK: Path to the Asylo sdk.
# -- MY_PROJECT: Path to the Examples repo.
# -- MESSAGE: Message you'd like to be encrypted
# -- CONFIG_TYPE: One of {sgx, sgx-sim}
# Start the provision server with the directions given at asylo/examples/remote/provision_server.
# ```bash
# export ASYLO_SDK=/opt/asylo/sdk
# export MY_PROJECT=/opt/asylo/examples
# export MESSAGE="Asylo Rocks"
# export CONFIG_TYPE=sgx-sim
# docker run -it --net=host \
#   -v ${ASYLO_SDK}:/opt/asylo/sdk \
#   -v ${MY_PROJECT}:/opt/asylo/examples \
#   -w /opt/asylo/examples/remote/quickstart \
#   gcr.io/asylo-framework/asylo:latest \
#   ./build.sh ${CONFIG_TYPE} "${MESSAGE}"
# ```

# If any command fails exit.
set -e

# Export all variables as environment variables.
set -a

# Default configuration for CONFIG_TYPE.
CONFIG_TYPE_DEFAULT=sgx

# Command line argument: Allows selection of local backend, if one is not
# selected it defaults to $CONFIG_DEFAULT
CONFIG_TYPE=${1:-$CONFIG_TYPE_DEFAULT}

# Set the ENCLAVE_TAG based on the CONFIG_TYPE. ENCLAVE_TAG is used as part of
# the ENCLAVE_TARGET.
if [ "$CONFIG_TYPE" == "sgx" ]; then
  ENCLAVE_TAG="sgx_hw";
elif [ "$CONFIG_TYPE" == "sgx-sim" ]; then
  ENCLAVE_TAG="sgx_sim";
fi

if [ -z "$ENCLAVE_TAG" ]; then
  echo "CONFIG_TYPE must be one of sgx or sgx-sim";
  exit;
fi

# Enclave to be used in the example.
ENCLAVE_TARGET=demo_enclave_debug_${ENCLAVE_TAG}.so

bazel build //remote/quickstart:${ENCLAVE_TARGET}

# Path where bazel puts built objects.
BAZEL_BIN_PATH=$(bazel info bazel-bin)
QUICK_PATH=${BAZEL_BIN_PATH}/remote/quickstart

# Path where bazel puts generated files - can be but not always the same as
# bazel-bin.
BAZEL_GEN_PATH=$(bazel info bazel-genfiles)
PROVISION_PATH=${BAZEL_GEN_PATH}/remote/provision_server

# Run the quickstart_remote example.
bazel run --define=ASYLO_REMOTE=1 //remote/quickstart:quickstart_remote -- \
          --message="$2" \
          --security_type=ssl \
          --ssl_key=${PROVISION_PATH}/server.key \
          --ssl_cert=${PROVISION_PATH}/server.crt \
          --enclave_path=${QUICK_PATH}/${ENCLAVE_TARGET} \
          --remote_provision_server=[::1]:4321 \
          --local_client_name=[::1]
