<!--jekyll-front-matter
---
title: Intel SGX hardware release enclaves
overview: Build, sign and launch an Intel SGX enclave in release mode.

location: /_docs/guides/sgx_release_enclaves.md
order: 30

layout: docs
type: markdown
toc: true
---
{% include home.html %}
jekyll-front-matter-->

## Overview

This is a step-by-step guide on how to use Asylo to produce and launch a release
enclave for the Intel SGX hardware backend. A release enclave may be run in
release mode, which disables inspection of the enclave's memory (e.g., by a
debugger) at a hardware level. Note that launching an SGX hardware enclave
requires that the user possesses an Intel-whitelisted enclave-signing key[^1].

This guide is suitable for users of the
[Asylo Docker image](https://github.com/google/asylo#build-environment-in-docker-recommended),
as well as users that followed the
[manual installation instructions](https://github.com/google/asylo/blob/master/INSTALL.md)
for Asylo and its dependencies.

## Procedure

Asylo provides utilities that make development and deployment of debug enclaves
simple. The process of building and signing a release enclave is more involved
since signing keys are typically stored in an isolated, offline signing facility
that is inaccessible from standard development flows[^2]. For this reason, the
process of building the enclave, signing the enclave, and combining the enclave
with the signature are broken into separate steps.

The high-level steps of this process are:

1.  Build the enclave for release and prepare data for signing.

2.  Sign the enclave material with an Intel-whitelisted enclave-signing key.

3.  Incorporate signed material into the enclave binary.

### Step 0: Setup

#### WORKSPACE configuration

Add the following to your project's WORKSPACE file to import Asylo and enable
Asylo's Bazel extensions to the Intel SGX SDK:

```python
http_archive(
    name = "com_google_asylo",
    urls = ["https://github.com/google/asylo/archive/<version>.tar.gz"],
    strip_prefix = "asylo-<version>",
    sha256 = "<insert hash here>",
)

load("//asylo/bazel:sgx_deps.bzl", "sgx_deps")
sgx_deps()
```

Note: SGX hardware support is available in Asylo since
[v0.3.0](https://github.com/google/asylo/releases/tag/v0.3.0).

#### Asylo Docker image users only

Set up up an environment variable that points to the root of your project's
source tree. This must be a Bazel workspace.

```shell
# Set this to your project's source tree.
MY_PROJECT=...
```

### Step 1: Define the enclave and release configuration

Define the enclave in your BUILD file using the `sgx_enclave` rule.

```python
load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave")

sgx_enclave(
  name = "enclave.so",
  config = ":release_config",
  ...
)
```

The `sgx_enclave` macro produces two targets:

*   `enclave_unsigned.so`, which is a `cc_binary` library object built with the
    Asylo toolchain. This binary will be used to produce the signed release
    enclave.
*   `enclave.so`, which is the `enclave_unsigned.so` binary signed using
    [Intel's enclave signing tool](https://software.intel.com/en-us/sgx-sdk-dev-reference-the-enclave-signing-tool)
    with a debug-only RSA key that is distributed with the Asylo codebase[^3].

The `sgx_enclave` macro takes an optional configuration in the `config`
parameter, which, by default, sets the enclave metadata to allow running the
enclave in debug mode (i.e. `disable_debug = false`). A custom configuration can
be defined with the
[`sgx_enclave_configuration`](https://github.com/google/asylo/blob/a6e1e5ec607ee9a3854134b32769f6873908d405/asylo/distrib/sgx_x86_64/linux_sgx_2_1_3.patch#L2970)
rule, a Bazel wrapper around the _Enclave Configuration File_ detailed in
Intel's
[developer reference materials](https://01.org/sites/default/files/documentation/intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf).
Below is a sample configuration that disallows running an enclave in debug mode:

```python
load("@linux_sgx//:sgx_sdk.bzl", "sgx_enclave_configuration")

sgx_enclave_configuration(
  name = "release_config",
  disable_debug = "1",
  prodid = "0",
  isvsvn = "0"
)
```

Refer to Intel's [developer guide](https://software.intel.com/en-us/node/702979)
for information on the _ISVPRODID_ and _ISVSVN_ values, which are denoted by the
`prodid` and `isvsvn` parameters respectively in the configuration above.

### Step 2: Build the unsigned enclave using the Asylo toolchain

As described above, the `enclave.so` binary produced by the `sgx_enclave` rule
is signed with a debug RSA key, and is not suitable for running in release mode.
The next step to producing a hardware enclave that runs in release mode is to
build an unsigned version of the enclave binary, and an associated release
config.

The following commands illustrate how to build an enclave (in this case
`//package/path:enclave.so`) and extract signing material. The enclave build
command can be invoked with any additional desired flags (e.g., `-c opt` for
optimization). Your project's `.bazelrc` is required to contain the Asylo config
aliases from
[Asylo's .bazelrc](https://github.com/google/asylo/blob/v0.3.0/.bazelrc).

```shell
# Prepare a temporary workspace.
RELEASE_DIR="$(mktemp --directory --tmpdir=/tmp)"

# Choose one of the following:
# [A] For users of Asylo Docker image.
DOCKER="docker run --rm \
  -e RELEASE_DIR="${RELEASE_DIR}" \
  -v bazel-cache:/root/.cache/bazel \
  -v "${MY_PROJECT}":/opt/my-project \
  -v "${RELEASE_DIR}":"${RELEASE_DIR}" \
  -w /opt/my-project \
  gcr.io/asylo-framework/asylo"
BAZEL="${DOCKER} bazel"
CP="${DOCKER} cp"
# [B] For users that manually installed Asylo and its dependencies.
BAZEL=bazel
CP=cp

# Build the unsigned enclave.
${BAZEL} build --config=sgx //package/path:enclave_unsigned.so
${CP} "$(${BAZEL} info bazel-bin)/package/path/enclave_unsigned.so" "${RELEASE_DIR}"

# Build the release configuration.
${BAZEL} build //package/path:release_config
${CP} "$(${BAZEL} info bazel-genfiles)/package/path/release_config.xml" "${RELEASE_DIR}"

# Generate signing data for the release enclave.
${BAZEL} run @linux_sgx//:sgx_sign_tool -- gendata \
  -enclave "${RELEASE_DIR}/enclave_unsigned.so" \
  -config "${RELEASE_DIR}/release_config.xml" \
  -out "${RELEASE_DIR}/release_data_to_sign"
```

### Step 3: Sign the release data

Bring a copy of `"${RELEASE_DIR}/release_data_to_sign"` to your offline signing
facility and sign it with your whitelisted private key. The exact steps required
to produce the signature will depend on your key storage facility (e.g., an
HSM). For OpenSSL usage, refer to Intel's
[OpenSSL examples](https://software.intel.com/en-us/sgx-sdk-dev-reference-openssl-examples)
guide.

### Step 4: Reincorporate the signed release data into the enclave binary

To produce the final enclave binary, the signature must be combined with the
original unsigned enclave binary using Intel's enclave signing tool. Copy the
signature (generated in the [previous step](#step-3-sign-the-release-data)) and
the public key to `"${RELEASE_DIR}"`. Note that the following commands assume
that `"${RELEASE_DIR}/release_data_to_sign.sig"` contains the signature and
`"${RELEASE_DIR}/signing_key.pem.pub"` contains the public key corresponding to
the private key used to produce the signature. `${BAZEL}` is defined as in
[Step 2](#step-2-build-the-unsigned-enclave-using-the-asylo-toolchain).

```shell
${BAZEL} run @linux_sgx//:sgx_sign_tool -- catsig \
  -enclave "${RELEASE_DIR}/enclave_unsigned.so" \
  -key "${RELEASE_DIR}/signing_key.pem.pub" \
  -config "${RELEASE_DIR}/release_config.xml" \
  -sig "${RELEASE_DIR}/release_data_to_sign.sig" \
  -unsigned "${RELEASE_DIR}/release_data_to_sign" \
  -out "${RELEASE_DIR}/enclave.so"
```

### Step 5: Launch the release enclave

To launch a release enclave, define a `cc_binary` target that encapsulates the
loader logic. See the
[Asylo Quickstart Guide](https://asylo.dev/docs/guides/quickstart.html#enclave-interaction-model)
for a review of the Asylo APIs that can be used to invoke an enclave from an
untrusted application.

The following example shows an invocation of a loader,
`//package/path:enclave_loader`, that accepts the path of the enclave binary via
a command-line flag (`--enclave_path`). Note that `--define=SGX_SIM=0` must be
passed to the Bazel command that builds the loader so that the SGX SDK is built
for hardware mode. If using the Asylo Docker image on an SGX-enabled host, note
that you can propagate the SGX capabilities from the host with the following
Docker flags:

*   `--device=/dev/isgx`
*   `-v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket`

```shell
# BAZEL must be redefined here for users of the Asylo Docker image.
DOCKER="docker run --rm --device=/dev/isgx \
  -e RELEASE_DIR="${RELEASE_DIR}" \
  -v bazel-cache:/root/.cache/bazel \
  -v "${MY_PROJECT}":/opt/my-project \
  -v "${RELEASE_DIR}":"${RELEASE_DIR}" \
  -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket \
  -w /opt/my-project \
  gcr.io/asylo-framework/asylo"
BAZEL="${DOCKER} bazel"

${BAZEL} run --define=SGX_SIM=0 //package/path:enclave_loader \
  -- --enclave_path="${RELEASE_DIR}/enclave.so"
```

## Notes

*   To launch a release enclave, the private key that signed the enclave must be
    on Intel's whitelist. You can get the latest version of the whitelist
    [here](http://whitelist.trustedservices.intel.com/SGX/LCWL/Linux/sgx_white_list_cert.bin).
    The whitelist must be installed on the machine as part of the PSW. The PSW
    may periodically contact the Internet to refresh the Intel key whitelist.
*   To run a release enclave built for the SGX hardware backend, you need access
    to SGX hardware.

[^1]: Only users that have a
    [commercial license agreement with Intel](https://software.intel.com/en-us/sgx/commercial-use-license-request)
    are authorized to run release mode Intel SGX enclaves via a whitelisted
    signing key. In release mode, the debug bit is unset, which means that
    enclave memory is guarded from inspection. Debug enclaves can have their
    memory inspected by attaching a debugger to the process. Users that wish
    to protect their secrets in production are thus advised to not deploy
    debug enclaves.

<!--Intentional comment to prevent formatting tools from removing this blank line-->

[^2]: Refer to Intel's recommendations for
    [Safeguarding the Enclave Signing Key](https://software.intel.com/en-us/node/702980).

<!--Intentional comment to prevent formatting tools from removing this blank line-->

[^3]: Enclaves signed with Asylo's debug-only RSA key have no additional
    security value and should _never_ be used to run sensitive workloads or
    handle sensitive data.
