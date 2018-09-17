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

# Start with a temporary image just for building the toolchain.
FROM debian:buster as toolchain

# Add build dependencies from Debian.
RUN apt-get update && \
    apt-get install -y \
        bison \
        build-essential \
        flex \
        libisl-0.18-dev \
        libmpc-dev \
        libmpfr-dev \
        rsync \
        texinfo \
        wget \
        zlib1g-dev

COPY . /opt/asylo/distrib/

# Build and install the toolchain.
RUN /opt/asylo/distrib/sgx_x86_64/install-toolchain \
    --system \
    --prefix /opt/asylo/toolchains/sgx_x86_64

## Now, create the final image.
FROM debian:buster

# Install development tools (gnupg is needed first for the apt-key).
COPY bazel-release.pub.gpg /tmp/
RUN apt-get update && \
    apt-get install -y gnupg && \
    echo "deb http://storage.googleapis.com/bazel-apt stable jdk1.8" \
        > /etc/apt/sources.list.d/bazel.list && \
    apt-key add /tmp/bazel-release.pub.gpg && \
    rm /tmp/bazel-release.pub.gpg && \
    apt-get update && \
    apt-get install -y \
        bazel \
        build-essential \
        libfl2 \
        libisl15 \
        ocaml-nox \
        ocamlbuild \
        openjdk-8-jdk-headless \
        python-jinja2 \
        vim \
        && \
    apt-get clean && \
    echo ". /etc/bash_completion" >> /root/.bashrc

# Copy the built toolchain from the earlier image.
COPY --from=toolchain /opt/asylo/toolchains/ /opt/asylo/toolchains/
COPY --from=toolchain /usr/local/share/asylo/ /usr/local/share/asylo/

# Default command to run if not specified otherwise.
CMD ["/bin/bash"]
