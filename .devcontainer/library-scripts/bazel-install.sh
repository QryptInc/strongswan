#!/bin/bash
set -euo pipefail
source "/tmp/library-scripts/lib.sh" # must match path set in Dockerfile

check_packages curl ca-certificates
apt_cleanup

echo "Installing Bazel"

LOCAL_BIN="/usr/local/bin"
BAZELISK_VERSION="v1.17.0"
BUILDIFIER_VERSION="v6.1.2"

github_download() {
	repo=$1
	version=$2
	artifact=$3
	output=$4
	if [ "${version}" = "latest" ]; then
		URL="https://github.com/${repo}/releases/latest/download/${artifact}"
	else
		URL="https://github.com/${repo}/releases/download/${version}/${artifact}"
	fi
	curl -fSsL "${URL}" -o "${output}"
}

arch="$(uname -m)"
case "${arch}" in
x86_64) ARCHITECTURE=amd64 ;;
aarch64 | arm64 | armv8*) ARCHITECTURE=arm64 ;;
*)
	echo -e "Unsupported '$arch' architecture"
	exit 1
	;;
esac

platf="$(uname -s)"
case "${platf}" in
Linux) PLATFORM=linux ;;
Darwin) PLATFORM=darwin ;;
*)
	echo -e "Unsupported '$platf' platform"
	exit 1
	;;
esac

github_download "bazelbuild/bazelisk" "${BAZELISK_VERSION}" "bazelisk-${PLATFORM}-${ARCHITECTURE}" "${LOCAL_BIN}/bazelisk"
chmod +x "${LOCAL_BIN}/bazelisk"
ln -s "${LOCAL_BIN}/bazelisk" "${LOCAL_BIN}/bazel"

github_download "bazelbuild/buildtools" "${BUILDIFIER_VERSION}" "buildifier-${PLATFORM}-${ARCHITECTURE}" "${LOCAL_BIN}/buildifier"
chmod +x "${LOCAL_BIN}/buildifier"

echo "Done"
