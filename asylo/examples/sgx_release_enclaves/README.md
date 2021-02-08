<!--jekyll-front-matter
---

title: Intel SGX hardware release enclaves

overview: Build, sign and launch an Intel SGX enclave in release mode.

location: /_docs/guides/sgx_release_enclaves.md

order: 90

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
requires that the user possesses an Intel-allowlisted enclave-signing key[^1].

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

1.  Define your enclave targets to explicitly produce their signing material and
    incorporate a signature (made in step 3) of it into a final signed enclave
    binary.

2.  Build the enclave signing material target to get the file to sign.

3.  Sign the enclave material with an enclave-signing key.

4.  Build the enclave target with the incorporated signature.

Steps 1 and 3 are supported by Asylo build rules.

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

Define the enclave in your BUILD file using the `sgx_unsigned_enclave`,
`sgx_generate_enclave_signing_material`, and `sgx_signed_enclave` rules.

```python
load("//asylo/bazel:sgx_rules.bzl", "sgx_cc_unsigned_enclave")
load("@linux_sgx//:sgx_sdk.bzl", "sgx")

sgx_cc_unsigned_enclave(
  name = "enclave_unsigned.so",
  ...
)

sgx.generate_enclave_signing_material(
    name = "enclave_signing_material",
    config = ":release_config",
    unsigned = ":enclave_unsigned.so",
)

sgx.signed_enclave(
    name = "enclave.so",
    public_key = "my_public_key.pub",
    signature = "enclave_signing_material.dat.sig",
    signing_material = ":enclave_signing_material",
)
```

In addition to the sources for the enclave, these rules depend on two extra
files:

1.  Your public key (example `my_public_key.pub`) must be in your source tree as
    a PEM file or a Bazel target that produces a PEM file.

2.  The file containing a signature over your enclave's signing material. The
    file must be present within this package. See
    [step 3](#step-3-sign-the-release-data) for how to generate this file. This
    allows the signed enclave binary to be fully reproducible from the specific
    code snapshot at which it was signed.

The three rules have the following purposes:

*   `sgx_cc_unsigned_enclave` produces a `cc_binary` library object built with
    the Asylo toolchain. This binary will be used to produce the signed release
    enclave.
*   `sgx.generate_enclave_signing_material` extracts the parts of the SGX
    sigstruct (see
    [Intel documentation](https://software.intel.com/en-us/node/702979)) that
    must be signed from `enclave_unsigned.so` and the provided config. This
    material is produced using the `gendata` command of
    [Intel's enclave signing tool](https://software.intel.com/en-us/sgx-sdk-dev-reference-the-enclave-signing-tool).
*   `sgx.signed_enclave` integrates the unsigned enclave with the config,
    signing material, and signature of the signing material to produce a signed
    enclave. The public key is required for validation of the final signature.

The `config` field for the latter two rules specifies security-critical
configuration bits for the enclave, and thus must be signed. For example, the
configuration can disallow running the enclave in debug mode (i.e.
`disable_debug = true`). A custom configuration can be defined with the
[`sgx_enclave_configuration`](https://asylo.dev/docs/reference/api/bazel/sgx_sdk_bzl.html#sgx_enclave_configuration)
rule, a Bazel wrapper around the _Enclave Configuration File_ detailed in
Intel's
[developer reference materials](https://01.org/sites/default/files/documentation/intel_sgx_sdk_developer_reference_for_linux_os_pdf.pdf).
Below is a sample configuration that disallows running an enclave in debug mode:

```python
load("@linux_sgx//:sgx_sdk.bzl", "sgx")

sgx.enclave_configuration(
  name = "release_config",
  disable_debug = "1",
  prodid = "0",
  isvsvn = "0"
)
```

Refer to Intel's [developer guide](https://software.intel.com/en-us/node/702979)
for information on the _ISVPRODID_ and _ISVSVN_ values, which are denoted by the
`prodid` and `isvsvn` parameters respectively in the configuration above.

### Step 2: Get the unsigned enclave's signing material built using the Asylo toolchain

When you build the signing material target with the appropriate build flags, it
will build the unsigned enclave target and extract the signing material into a
file.

The following commands illustrate how to produce enclave signing material (in
this case `//package/path:enclave_signing_material`). The enclave build command
can be invoked with any additional desired flags (e.g., `-c opt` for
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

# Build the signing material target.
${BAZEL} build //package/path:enclave_signing_material_sgx_hw

# Copy out the generated signing material in order to sign it.
${CP} "$(${BAZEL} info bazel-bin)/package/path/enclave_signing_material.dat" "${RELEASE_DIR}"
```

### Step 3: Sign the release data

Bring a copy of `"${RELEASE_DIR}/enclave_signing_material.dat"` to your offline
signing facility and sign it with your allowlisted private key. The exact steps
required to produce the signature will depend on your key storage facility
(e.g., an HSM). For OpenSSL usage, refer to Intel's
[OpenSSL examples](https://software.intel.com/en-us/sgx-sdk-dev-reference-openssl-examples)
guide.

### Step 4: Reincorporate the signed release data into the enclave binary

The final enclave binary, `enclave_sgx_hw.so`, can be produced once you have the
signed signing material in your code tree. The example signature file is named
`enclave_signing_material.dat.sig`. The `sgx.signed_enclave` rule combines all
the necessary components for a signed enclave.

```shell
${BAZEL} build :enclave_sgx_hw.so
```

### Step 5: Launch the release enclave

To launch a release enclave, define a `cc_binary` target that encapsulates the
loader logic. See the
[Asylo Quickstart Guide](https://asylo.dev/docs/guides/quickstart.html#enclave-interaction-model)
for a review of the Asylo APIs that can be used to invoke an enclave from an
untrusted application.

The following example shows an invocation of a loader,
`//package/path:enclave_loader`, that accepts the path of the enclave binary via
a command-line flag (`--enclave_path`). Note that
`--@com_google_asylo_backend_provider//:backend=@linux_sgx//:asylo_sgx_hw` must
be passed to the Bazel command that builds the loader so that the SGX SDK is
built for hardware mode. If using the Asylo Docker image on an SGX-enabled host,
note that you can propagate the SGX capabilities from the host with the
following Docker flags:

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

${BAZEL} run --@com_google_asylo_backend_provider//:backend=@linux_sgx//:asylo_sgx_hw \
  //package/path:enclave_loader -- --enclave_path="${RELEASE_DIR}/enclave.so"
```

## Notes

*   To launch a release enclave, the private key that signed the enclave must be
    on Intel's allowlist. You can get the latest version of the allowlist
    [here](http://whitelist.trustedservices.intel.com/SGX/LCWL/Linux/sgx_white_list_cert.bin).
    The allowlist must be installed on the machine as part of the PSW. The PSW
    may periodically contact the Internet to refresh the Intel key allowlist.
*   To run a release enclave built for the SGX hardware backend, you need access
    to SGX hardware.

[^1]: Unless configured to use
    [Flexible Launch Control](https://software.intel.com/en-us/blogs/2018/12/09/an-update-on-3rd-party-attestation)
    with a
    [DCAP tree kernel driver](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver/linux),
    only users that have a
    [commercial license agreement with Intel](https://software.intel.com/en-us/articles/intel-software-guard-extensions-product-licensing-faq)
    are authorized to run release mode Intel SGX enclaves via a allowlisted
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
