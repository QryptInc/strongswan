#!/usr/bin/env bash

set -euo pipefail

# Install a specific version of Conan
python3 -m pip install conan==2.8.1
conan --version

# Check the system architecture
ARCH="$(uname -m)"

if [ "$ARCH" == "x86_64" ]; then
	echo "Detected x86_64 (amd64). Installing linux-x86_64 config..."
	conan config install-pkg \
		conanconfig/linux-x86_64@qrypt/dev \
		--url http://10.151.17.4:8082/artifactory/api/conan/conan-local
elif [ "$ARCH" == "aarch64" ]; then
	echo "Detected ARM64 (aarch64). Installing linux-aarch64 config..."
	conan config install-pkg \
		conanconfig/linux-aarch64@qrypt/dev \
		--url http://10.151.17.4:8082/artifactory/api/conan/conan-local
else
	echo "Unsupported architecture: $ARCH"
	# Optionally, exit or handle differently
	exit 1
fi
