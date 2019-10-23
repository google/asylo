#!/bin/bash
set -e
CONFIG_TYPE=${1:-sgx}

# Script for building the bouncing circles example.
#
# Asylo toolchain has difficulties building with two --config types. This script
# allows users to build the example enclaves with --config=sgx or sgx-sim, and
# the rest of the application without the --config= designation.
#
# Instructions for use:
# Set environment variables ASYLO_SDK, MY_PROJECT, and CONFIG_TYPE.
# -- ASYLO_SDK: Path to the Asylo sdk.
# -- MY_PROJECT: Path to the Examples repo.
# -- CONFIG_TYPE: One of {sgx, sgx-sim}
# Start the provision server with the directions given at asylo/examples/remote/provision_server.
# ```bash
# docker run --it --net=host \
#   -v ${ASYLO_SDK}:/opt/asylo/sdk \
#   -v ${MY_PROJECT}:/opt/asylo/examples \
#   -w /opt/asylo/examples/remote/bouncing_circles \
#   gcr.io/asylo-framework/asylo:latest \
#   ./build.sh ${CONFIG_TYPE}
# ```
#
# then open a browser window at
# http://<host machine>:8888/
# and follow the link
bazel clean

# Build the circle enclaves.
for ENCLAVE_NUM in {0..3}
do
  bazel build --config=${CONFIG_TYPE} \
    //remote/bouncing_circles:circle_enclave_${ENCLAVE_NUM}_debug.so
done

BAZEL_BIN_PATH=$(bazel info bazel-bin)
CIRCLES_PATH=${BAZEL_BIN_PATH}/remote/bouncing_circles
BAZEL_GEN_PATH=$(bazel info bazel-genfiles)
PROVISION_PATH=${BAZEL_GEN_PATH}/external/com_google_asylo/asylo/examples/remote/provision_server
bazel run //remote/bouncing_circles:web_application_remote -- \
            --port=8888 \
            --security_type=ssl \
            --ssl_key=${PROVISION_PATH}/server.key  \
            --ssl_cert=${PROVISION_PATH}/server.crt \
            --enclave_binary_paths=${CIRCLES_PATH}/circle_enclave_0_debug.so,${CIRCLES_PATH}/circle_enclave_1_debug.so,${CIRCLES_PATH}/circle_enclave_2_debug.so,${CIRCLES_PATH}/circle_enclave_3_debug.so \
            --remote_provision_server=[::1]:4321 \
            --local_client_name=[::1]
