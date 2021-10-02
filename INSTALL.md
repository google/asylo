# Asylo - Manual Installation

The following steps can be used to manually install
[Asylo](https://github.com/google/asylo) and its dependencies. The manual
installation process and Docker image creation process have both primarily been
tested on Debian Buster, but may also be used to install Asylo on other Linux
distros and versions.

See the [README.md](README.md) for instructions on Docker usage, which is our
recommended way of using the Asylo framework.

## Asylo sources

Clone the Asylo project from GitHub into a directory of your choice.

```bash
ASYLO="${HOME}"/asylo
git clone https://github.com/google/asylo.git "${ASYLO}"/sdk
```

## Toolchain

The Asylo framework uses a custom toolchain to compile enclave applications for
various backend environments. For example, to build your application for a
simulated SGX enclave backend, use the `sgx-sim` config.

```bash
bazel build --config=sgx-sim :my_app
```

If using macros defined by `asylo.bzl` or `sgx_sdk.bzl`, then `--config=sgx-sim`
*is not* the correct way to build your application. Those enclave/test/loader
targets will instead directly transition to the Asylo toolchain and build with a
number of supported enclave backends. A target defined by Asylo's
backend-generic macros is given a suffix like `_sgx_sim` to denote which backend
it uses.

You can manually install the toolchain by following these steps:

1.  Download and install the following prerequisites, which are needed for
    building the toolchain:

    *   bison
    *   build-essential
    *   flex
    *   libisl-dev
    *   libmpc-dev
    *   libmpfr-dev
    *   rsync
    *   texinfo
    *   wget
    *   zlib1g-dev

    For example, on Debian:

    ```bash
    sudo apt install bison build-essential flex libisl-dev libmpc-dev \
        libmpfr-dev rsync texinfo wget zlib1g-dev
    ```

1.  Build and install the toolchain.

    ```bash
    "${ASYLO}"/sdk/asylo/distrib/toolchain/install-toolchain \
        --user \
        --prefix "${ASYLO}"/toolchains/default
    ```

    This will install the toolchain under `"${ASYLO}"/toolchains/default`

See [toolchain/README.md](/asylo/distrib/toolchain/README.md) for additional
details on installing the toolchain.

## Intel SGX SDK

The Asylo framework uses
[Intel SGX SDK v2.9](https://github.com/intel/linux-sgx/blob/sgx_2.9/README.md)
with a [patch](asylo/distrib/sgx_x86_64/linux_sgx_2_9.patch) that backports some
pull requests and applies minor changes needed to build the SDK with the Asylo
toolchain.

## Intel SGX hardware backend support

Intel SGX hardware support requires additional dependencies. The process of
installing these dependencies is detailed in the
[Intel SGX SDK README](https://github.com/intel/linux-sgx/blob/master/README.md).
Namely, you must

*   build and install the
    [Linux SGX driver](https://github.com/intel/linux-sgx-driver),
*   build and install the
    [plaform software (PSW)](https://github.com/intel/linux-sgx/blob/master/README.md#install-the-intelr-sgx-psw),
    and
*   [start the Architectural Enclave Service Manager](https://github.com/intel/linux-sgx#start-or-stop-aesmd-service).

## Bazel

The Asylo framework is built with Bazel, Google's open source build tool.

You can manually install Bazel by following these steps:

```bash
sudo apt install curl gnupg
curl https://bazel.build/bazel-release.pub.gpg | sudo apt-key add -
echo "deb http://storage.googleapis.com/bazel-apt stable jdk1.8" | \
    sudo tee /etc/apt/sources.list.d/bazel.list
sudo apt update
sudo apt install bazel
```

## Additional dependencies

The following packages are used by Asylo and its dependencies, and must also be
installed.

*   git
*   ocaml-nox
*   ocamlbuild
*   python3

On Debian, these can be installed with the following command:

```bash
sudo apt install git ocaml-nox ocamlbuild
```

## Next steps

Refer to [the project README](README.md#examples-1) for using this Asylo
installation.
