#!/usr/bin/env bash
set -euo pipefail

CONAN_HOME_DIR="$1"
DEPLOY_DIR="$2"
ARCH="$3"
mkdir -p "$DEPLOY_DIR"

export CONAN_HOME="$CONAN_HOME_DIR"

PROFILE=""

if [ "$ARCH" == "x86_64" ]; then
    PROFILE="linux-x86_64"
elif [ "$ARCH" == "aarch64" ]; then
    PROFILE="linux-aarch64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

conan install \
    --requires qryptsdkwrapper/0.12.2@qrypt/dev \
    -o "&:language=c" \
    --profile "$PROFILE" \
    --deployer-package="&" \
    --deployer-folder="$DEPLOY_DIR"

echo "SDK placed in $DEPLOY_DIR"
