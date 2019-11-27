<!--jekyll-front-matter
---

title: Remote Backend Bouncing Circles Guide

overview: Demonstrate multiple enclaves running remotely

location: /_docs/guides/bouncing_circles.md

order: 55

layout: docs

type: markdown

toc: true

---
{% include home.html %}
jekyll-front-matter-->

## Introduction

This guide demonstrates more elaborate usage of Asylo with a Remote Backend. It
assumes the reader has knowledge introduced in the
[Remote Quickstart Guide](https://asylo.dev/docs/guides/remote_quickstart.html).

The bouncing circles web application uses four separate enclaves to track four
circles. A simple web server accesses each enclave via the remote enclave
backend. Each enclave, once initialized, holds color, location, radius and speed
of the circle it owns, rendering them isolated from the outer world. The web
application makes an EnterAndRun call to each of the 4 enclaves, gets back
color, location and radius and draws the circle.

This example provides two frameworks that are accessed identically by the remote
backend: local and remote. Both of them provision RemoteEnclaveProxyServer, but
do it differently:

-   local version runs the enclaves on the same machine as the application

-   remote version runs the enclaves on an SGX-enabled machine while the Web
    Application can be run on a non-SGX machine.

## Local version - still remote backend, but both running on the same machine

### Building

To build the application and the enclaves:

```bash
export CONFIG_TYPE=sgx # Or sgx-sim if not running on SGX-enabled hardware.
bazel build :web_application --config=${CONFIG_TYPE} --define=ASYLO_REMOTE=1
```

Note: The `CONFIG_TYPE=sgx` flag selects our enclave cross compiler toolchain,
which builds code to run inside enclaves. To run on non-SGX hardware, specify
simulated SGX flag `CONFIG_TYPE=sgx-sim`.

### Running

To run the program, invoke the application binary (from bazel-bin):

```bash
$(bazel info bazel-bin)/remote/bouncing_circles/web_application \
   --remote_proxy="$(bazel info bazel-bin)/remote/bouncing_circles/web_application"
```

and then open a browser window at `http://<host machine>:8888/` and follow the
link named "circles".

## Remote backend running enclaves on another machine than the application

The previous demo launched the application with local provisioning.

To make it truly remote, we will now now utilize remote provisioning with our
example remote
[provision server](https://github.com/google/asylo/tree/master/asylo/examples/remote/provision_server)
and run the same application with enclaves deployed on another docker image.

First, if you haven't already done so, download the Asylo SDK and Examples
repos:

```bash
export ASYLO_SDK=~/asylo-sdk
git clone https://github.com/google/asylo.git "${ASYLO_SDK}"
export MY_PROJECT=~/asylo-examples
mkdir -p "${MY_PROJECT}"
wget -q -O - https://github.com/google/asylo-examples/archive/master.tar.gz | \
    tar -zxv --strip 1 --directory "${MY_PROJECT}"
```

Next, run the provision server:

```bash
docker run -it --net=host \
    -v ${ASYLO_SDK}:/opt/asylo/sdk \
    -v ${MY_PROJECT}:/opt/asylo/examples \
    -w /opt/asylo/examples/remote/provision_server \
    gcr.io/asylo-framework/asylo:latest \
    ./build.sh
```

Once the provisioning server reports that it is listening to port `4321`
(configurable), run the container with the following command:

```bash
export CONFIG_TYPE=sgx # Or sgx-sim if Remote Provision server isn't running on SGX-enabled hardware.
docker run -it --net=host \
    -v ${ASYLO_SDK}:/opt/asylo/sdk \
    -v ${MY_PROJECT}:/opt/asylo/examples \
    -w /opt/asylo/examples/remote/bouncing_circles \
    gcr.io/asylo-framework/asylo:latest \
    ./build.sh ${CONFIG_TYPE}
```

After the application started, open a browser window at `http://<host
machine>:8888/` and follow the link named "circles".
