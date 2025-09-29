# Use Ubuntu 22.04 as the base image to get GLIBC 2.35
FROM ubuntu:22.04

# Options for setup script
ARG INSTALL_ZSH="true"
ARG UPGRADE_PACKAGES="false"
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID

# Install needed packages and setup non-root user. Use a separate RUN statement to add your own dependencies.
COPY library-scripts/*.sh /tmp/library-scripts/

# Install common dependencies and setup user
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && /bin/bash /tmp/library-scripts/common-debian.sh "${INSTALL_ZSH}" "${USERNAME}" "${USER_UID}" "${USER_GID}" "${UPGRADE_PACKAGES}" "true" "true" \
    && apt-get install -y pkg-config zip g++ zlib1g-dev unzip python3

# Install Bazel
RUN /bin/bash /tmp/library-scripts/bazel-install.sh

# Install required packages for adding repositories
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    software-properties-common

# Add x86_64 architecture for cross-compilation
ARG TARGETARCH
RUN if [ $TARGETARCH = "arm64" ]; then \
			dpkg --add-architecture amd64 \
		; fi

# Create a new sources file specifically for amd64 packages
RUN if [ $TARGETARCH = "arm64" ]; then \
			echo "deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ jammy main restricted universe multiverse" > /etc/apt/sources.list.d/amd64-sources.list && \
			echo "deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list.d/amd64-sources.list && \
			echo "deb [arch=amd64] http://archive.ubuntu.com/ubuntu/ jammy-backports main restricted universe multiverse" >> /etc/apt/sources.list.d/amd64-sources.list && \
			echo "deb [arch=amd64] http://security.ubuntu.com/ubuntu/ jammy-security main restricted universe multiverse" >> /etc/apt/sources.list.d/amd64-sources.list \
		; fi

# Make sure original sources are marked for ARM only
# Backup original sources file
RUN if [ $TARGETARCH = "arm64" ]; then \
			cp /etc/apt/sources.list /etc/apt/sources.list.backup && \
			cat /etc/apt/sources.list.backup | sed 's/^deb /deb [arch=arm64,armhf] /g' > /etc/apt/sources.list \
		; fi

# Install additional dependencies
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    protobuf-compiler \
    libprotobuf-dev \
    libssl-dev \
    libsystemd-dev \
    ninja-build \
    cmake \
    build-essential \
    gcc \
    gdb \
    graphviz \
    netcat \
    fzf \
    fakeroot \
    ripgrep \
    autojump \
    tmux \
    fish \
    ubuntu-dev-tools \
    fakeroot \
    libsystemd-dev \
    debhelper \
    g++-x86-64-linux-gnu \
    libc6-dev-amd64-cross \
		libssl-dev:amd64 \
		libclang-dev \
		clangd-12 \
    libsystemd-dev:amd64 \
    shtool \
    gperf \
    bison \
    libgmp3-dev \
    flex \
    libjansson-dev \
    libcurl4-openssl-dev \
    redis \
    astyle \
    python3-pytest \
    python3-pytest-xdist \
    unzip \
    xsltproc \
    doxygen \
    python3-yaml \
    python3-pip \
    valgrind \
    && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/* /tmp/library-scripts
