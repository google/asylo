# Asylo toolchain - a toolchain to build enclave binaries for Asylo.

Copyright 2018 Asylo authors

## Build the Asylo toolchain

### Prerequisites:

-   Ensure that you have one of the following supported operating systems:

    *   Ubuntu\* Desktop-16.04-LTS 64bits
    *   Debian buster

-   Use the following command(s) to install the required tools to build the
    Asylo toolchain:

    *   On Ubuntu 16.04 or Debian buster

    ```shell
    sudo apt-get install -y bison \
        build-essential flex libisl-dev libmpc-dev libmpfr-dev rsync texinfo \
        zlib1g-dev wget
    ```

### Installation command:

To build and install the Asylo toolchain, run the following command:

`./install-toolchain [--prefix=install-path]`

#### Troubleshooting:

You may need set an https proxy for the `wget` tool used by the script (such as
`export https_proxy=http://proxy-host:proxy-port`).

If you don't have access to a network, you can opt out of the `wget` dependency
fetches with the `--no_fetch` argument, and supply your own archives or paths to
sources with the `--newlib`, `--gcc`, and `--binutils` arguments.
