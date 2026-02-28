set -euo pipefail

CONAN_HOME_DIR="$1"
ARCH="$2"
mkdir -p "$CONAN_HOME_DIR"

export CONAN_HOME="$CONAN_HOME_DIR"

# Bootstrap pip if needed, then install conan into a temporary directory.
# We avoid `python3 -m pip` and `python3 -m venv` because Bazel sandbox
# environments may lack both the pip module and the ensurepip/venv packages.
PIP_DIR="$(mktemp -d)"
export PYTHONUSERBASE="$PIP_DIR"
if ! python3 -m pip --version >/dev/null 2>&1; then
    curl -sSL https://bootstrap.pypa.io/get-pip.py | python3 - --user --quiet
fi
python3 -m pip install --user --quiet conan==2.8.1
export PATH="$PIP_DIR/bin:$PATH"

if [ "$ARCH" == "x86_64" ]; then
    echo "Detected x86_64. Installing linux-x86_64 config..."
    conan config install-pkg \
        conanconfig/linux-x86_64@qrypt/dev \
        --url http://10.151.17.4:8082/artifactory/api/conan/conan-local
elif [ "$ARCH" == "aarch64" ]; then
    echo "Detected ARM64. Installing linux-aarch64 config..."
    conan config install-pkg \
        conanconfig/linux-aarch64@qrypt/dev \
        --url http://10.151.17.4:8082/artifactory/api/conan/conan-local
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

echo "Conan home configured in $CONAN_HOME"
