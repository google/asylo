# RemoteProxyProvisionServer Launching Guide

## Introduction

This launching guide assumes that it is being used to setup a
`RemoteProxyProvisionServer` for other examples:

*   [Remote quickstart](https://asylo.dev/docs/guides/remote_quickstart.html)

*   [Bouncing circles](https://asylo.dev/docs/guides/bouncing_circles.html)

For more details please refer to:

*   [Asylo Remote Backend](https://asylo.dev/docs/concepts/remote-backend.html)

## Building and launching RemoteProxyProvisionServer

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

Finally, launch the `RemoteProxyProvisionServer` in the Asylo docker container:

```bash
docker run -it --net=host \
    -v ${ASYLO_SDK}:/opt/asylo/sdk \
    -v ${MY_PROJECT}:/opt/asylo/examples \
    -w /opt/asylo/examples/remote/provision_server \
    gcr.io/asylo-framework/asylo:latest \
    ./build.sh
```

After that, applications can be run and rely on this server to deploy enclaves
remotely. The default listening port is `4321`.
