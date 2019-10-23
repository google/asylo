#!/bin/bash
set -e
CONFIG_TYPE=${2:-sgx}

# Script for building the quickstart example.
#
# Asylo toolchain has difficulties building with two --config types. This script
# allows users to build the example enclaves with --config=sgx or sgx-sim, and
# the rest of the application without the --config= designation.
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
#   ./build.sh "${MESSAGE}" ${CONFIG_TYPE}
# ```
bazel build --config=${CONFIG_TYPE} //remote/quickstart:demo_enclave_debug.so

BAZEL_BIN_PATH=$(bazel info bazel-bin)
QUICK_PATH=${BAZEL_BIN_PATH}/remote/quickstart

BAZEL_GEN_PATH=$(bazel info bazel-genfiles)
PROVISION_PATH=${BAZEL_GEN_PATH}/external/com_google_asylo/asylo/examples/remote/provision_server
bazel run //remote/quickstart:quickstart_remote -- \
          --message="$1" \
          --security_type=ssl \
          --ssl_key=${PROVISION_PATH}/server.key \
          --ssl_cert=${PROVISION_PATH}/server.crt \
          --enclave_path=${QUICK_PATH}/demo_enclave_debug.so \
          --remote_provision_server=[::1]:4321 \
          --local_client_name=[::1]

