#!/bin/bash
set -e

# Script for building the Provision Server Container
#
# Instructions for use:
# Set environment variables ASYLO_SDK and MY_PROJECT.
# -- ASYLO_SDK: Path to the Asylo sdk.
# -- MY_PROJECT: Path to the Examples repo.
# docker run -it --net=host \
#   -v ${ASYLO_SDK}:/opt/asylo/sdk \
#   -v ${MY_PROJECT}:/opt/asylo/examples \
#   -w /opt/asylo/examples/remote/provision_server \
#   gcr.io/asylo-framework/asylo:latest \
#   ./build.sh
# Build the provision server and remote proxy.
TMP_BUILD_FOLDER=/tmp/asylo/build
mkdir -p ${TMP_BUILD_FOLDER}

pushd /opt/asylo/sdk
bazel build //asylo/util/remote:remote_provision_host_server
bazel build //asylo/util/remote:sgx_remote_proxy
bazel build //asylo/util/remote:remote_provision_host_server_host_loader
BAZEL_BIN_PATH=$(bazel info bazel-bin)
cp -r ${BAZEL_BIN_PATH}/asylo/util/remote/* ${TMP_BUILD_FOLDER}
popd

# Decode the certs.
bazel build //remote/provision_server:certs

BAZEL_GEN_PATH=$(bazel info bazel-genfiles)
cp -r ${BAZEL_GEN_PATH}/remote/provision_server/* ${TMP_BUILD_FOLDER}

${TMP_BUILD_FOLDER}/remote_provision_host_server_host_loader \
  --security_type=ssl \
  --ssl_key=${TMP_BUILD_FOLDER}/server.key \
  --ssl_cert=${TMP_BUILD_FOLDER}/server.crt \
  --port=4321 \
  --remote_proxy=${TMP_BUILD_FOLDER}/sgx_remote_proxy
