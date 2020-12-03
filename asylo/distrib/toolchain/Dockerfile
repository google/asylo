#
# Copyright 2018 Asylo authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Use fixed snapshot of Debian to create a deterministic environment.
# Snapshot tags can be found at https://hub.docker.com/r/debian/snapshot/tags
ARG debian_snapshot=buster-20201012

# Start with a temporary image just for building the toolchain.
FROM debian/snapshot:${debian_snapshot} as toolchain

# Add build dependencies from Debian.
RUN apt-get update && \
    apt-get -o Acquire::Retries=5 -o Acquire::http::Dl-Limit=800 install -y \
        bison \
        build-essential \
        flex \
        libisl-dev \
        libmpc-dev \
        libmpfr-dev \
        rsync \
        texinfo \
        wget \
        zlib1g-dev

COPY . /opt/asylo/distrib/toolchain/

# Build and install the toolchain.
RUN /opt/asylo/distrib/toolchain/install-toolchain \
    --system \
    --prefix /opt/asylo/toolchains/default

# Now, create the final image.
FROM debian/snapshot:${debian_snapshot}

# Use a fixed version of Bazel.
ARG bazel_version=3.7.0
ARG bazel_sha=2fc8dfb85328112a9d67f614e33026be74c2ac95645ed8e88896366eaa3d8fc3
ARG bazel_url=https://storage.googleapis.com/bazel-apt/pool/jdk1.8/b/bazel/bazel_${bazel_version}_amd64.deb

# Install development tools
RUN apt-get update && \
    apt-get install -y wget && \
    wget "${bazel_url}" -nv -o- -O bazel.deb && \
    echo "${bazel_sha}  bazel.deb" > bazel.sha256 && \
    sha256sum --check bazel.sha256 && \
    apt-get -o Acquire::Retries=5 -o Acquire::http::Dl-Limit=800 install -y \
        ./bazel.deb \
        bash-completion \
        build-essential \
        default-jdk-headless \
        git \
        libfl2 \
        ocaml-nox \
        ocamlbuild \
        python-dev \
        python2.7-dev \
        python3-dev \
        vim \
        && \
    rm bazel.deb bazel.sha256 && \
    apt-get clean && \
    echo ". /etc/bash_completion" >> /root/.bashrc

# Copy the built toolchain from the earlier image.
COPY --from=toolchain /opt/asylo/toolchains/ /opt/asylo/toolchains/
COPY --from=toolchain /usr/local/share/asylo/ /usr/local/share/asylo/

# Default command to run if not specified otherwise.
CMD ["/bin/bash"]
