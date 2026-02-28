set -euo pipefail

CONAN_HOME_DIR="$1"
ARCH="$2"
mkdir -p "$CONAN_HOME_DIR"

export CONAN_HOME="$CONAN_HOME_DIR"

VENV_DIR="$(mktemp -d)"
python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

python3 -m pip install conan==2.8.1

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
