#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

OUT_DIR="$ROOT_DIR/dist"
mkdir -p "$OUT_DIR"

if ! command -v go >/dev/null 2>&1; then
    echo "error: go is not installed" >&2
    exit 1
fi

if [[ ! -f VERSION.json ]]; then
    echo "error: VERSION.json not found" >&2
    exit 1
fi
VERSION="$(python3 -c "import json; print(json.load(open('VERSION.json'))['version'])")"
[[ -n "$VERSION" ]] || {
    echo "error: version missing from VERSION.json" >&2
    exit 1
}

echo "Using $(go env GOVERSION)"
echo "Version ${VERSION}"
echo

build_one() {
    local os="$1"
    local arch="$2"
    local name="losdias-verify"
    if [[ "$os" == "windows" ]]; then
        name="${name}.exe"
    fi
    if [[ "${3:-}" == "release" ]]; then
        name="losdias-verify-${os}-${arch}"
        if [[ "$os" == "windows" ]]; then
            name="${name}.exe"
        fi
    fi
    echo "Building $name ($os/$arch)"
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "$OUT_DIR/$name" .
}

if [[ "${1:-}" == "all" ]]; then
    build_one darwin arm64 release
    build_one darwin amd64 release
    build_one linux amd64 release
    build_one linux arm64 release
    build_one windows amd64 release
else
    build_one "$(go env GOOS)" "$(go env GOARCH)"
fi

echo
echo "Verifier ready:"
ls -lh "$OUT_DIR"
