#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DIST_DIR="${ROOT_DIR}/dist"
VERSION_FILE="${ROOT_DIR}/VERSION.json"

DARWIN_ARM64="${DIST_DIR}/losdias-verify-darwin-arm64"
DARWIN_AMD64="${DIST_DIR}/losdias-verify-darwin-amd64"
LINUX_AMD64="${DIST_DIR}/losdias-verify-linux-amd64"
LINUX_ARM64="${DIST_DIR}/losdias-verify-linux-arm64"
WINDOWS_AMD64="${DIST_DIR}/losdias-verify-windows-amd64.exe"

NOTES=""
GH_REPO="AENGIX/losdias-verifier"

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: ./release.sh [-n|--notes TEXT] [NOTES]

Build losdias-verify for every release target, then create a GitHub release.

Tag format: v{version} from VERSION.json

Options:
  -n, --notes TEXT   Release notes (prompted if omitted)
  -h, --help         Show this help
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required"
}

json_version() {
  local file="$1"
  [[ -f "$file" ]] || die "version file not found: $file"
  python3 -c "import json; print(json.load(open('${file}'))['version'])" \
    || die "failed to read version from $file"
}

require_artifact() {
  local path="$1"
  [[ -f "$path" && -s "$path" ]] || die "missing or empty artifact: $path"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      -n|--notes)
        [[ $# -ge 2 ]] || die "--notes requires a value"
        NOTES="$2"
        shift 2
        ;;
      --)
        shift
        break
        ;;
      -*)
        die "unknown option: $1"
        ;;
      *)
        if [[ -n "$NOTES" ]]; then
          die "unexpected argument: $1"
        fi
        NOTES="$1"
        shift
        ;;
    esac
  done

  if [[ $# -gt 0 ]]; then
    if [[ -n "$NOTES" ]]; then
      die "unexpected argument: $1"
    fi
    NOTES="$*"
  fi
}

prompt_notes() {
  if [[ -n "$NOTES" ]]; then
    return 0
  fi
  if [[ ! -t 0 ]]; then
    die "release notes required (pass -n/--notes or a positional argument)"
  fi
  echo "Enter release notes (end with Ctrl-D):"
  NOTES="$(cat)"
  [[ -n "${NOTES//[[:space:]]/}" ]] || die "release notes cannot be empty"
}

require_release_commit() {
  local toplevel origin head upstream
  toplevel="$(git -C "$ROOT_DIR" rev-parse --show-toplevel 2>/dev/null || true)"
  # This tree also lives inside the site repo. A nested checkout must not
  # inherit that origin; the release always targets AENGIX/losdias-verifier.
  if [[ "$toplevel" != "$ROOT_DIR" ]]; then
    return 0
  fi
  origin="$(git -C "$ROOT_DIR" remote get-url origin 2>/dev/null || true)"
  [[ "$origin" == *losdias-verifier* ]] \
    || die "origin must be the AENGIX/losdias-verifier repository"
  [[ -z "$(git -C "$ROOT_DIR" status --porcelain)" ]] \
    || die "working tree is not clean"
  git -C "$ROOT_DIR" fetch origin
  head="$(git -C "$ROOT_DIR" rev-parse HEAD)"
  upstream="$(git -C "$ROOT_DIR" rev-parse '@{u}' 2>/dev/null || true)"
  [[ -n "$upstream" ]] || die "branch has no upstream; push it before releasing"
  [[ "$head" == "$upstream" ]] || die "push this commit before releasing"
}

build_verifier() {
  echo "==> Building verifier binaries"
  "${ROOT_DIR}/build.sh" all
  require_artifact "$DARWIN_ARM64"
  require_artifact "$DARWIN_AMD64"
  require_artifact "$LINUX_AMD64"
  require_artifact "$LINUX_ARM64"
  require_artifact "$WINDOWS_AMD64"
  echo "OK: $DARWIN_ARM64"
  echo "OK: $DARWIN_AMD64"
  echo "OK: $LINUX_AMD64"
  echo "OK: $LINUX_ARM64"
  echo "OK: $WINDOWS_AMD64"
  echo
}

create_github_release() {
  local tag="$1"
  echo "==> Creating GitHub release: ${tag}"
  require_cmd gh
  gh auth status >/dev/null 2>&1 || die "gh is not authenticated (run: gh auth login)"

  if gh release view "$tag" --repo "$GH_REPO" >/dev/null 2>&1; then
    die "release already exists for tag: $tag"
  fi

  gh release create "$tag" \
    --repo "$GH_REPO" \
    --target main \
    --title "$tag" \
    --notes "$NOTES" \
    "$DARWIN_ARM64" \
    "$DARWIN_AMD64" \
    "$LINUX_AMD64" \
    "$LINUX_ARM64" \
    "$WINDOWS_AMD64"

  echo
  echo "Release created:"
  gh release view "$tag" --repo "$GH_REPO" --json url -q .url
}

main() {
  parse_args "$@"
  prompt_notes

  require_cmd python3
  require_cmd go
  require_cmd git
  require_cmd gh

  local ver tag
  ver="$(json_version "$VERSION_FILE")"
  [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be major.minor.patch, got: $ver"
  tag="v${ver}"

  echo "Release tag: ${tag}"
  echo

  require_release_commit
  build_verifier

  create_github_release "$tag"
}

main "$@"
