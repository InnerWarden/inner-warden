#!/usr/bin/env bash
# Build the InnerWarden Community .deb and .rpm packages for amd64 and arm64
# from prebuilt Linux binaries, using nfpm. No dpkg or rpmbuild toolchain
# required. Resolves packaging/nfpm.yaml per architecture (nfpm does not expand
# env vars in the contents src glob reliably, so we substitute here).
#
# Usage:
#   packaging/build-linux-packages.sh <version> <amd64-binary> <arm64-binary> [outdir]
set -euo pipefail

VERSION="${1:?usage: build-linux-packages.sh <version> <amd64-binary> <arm64-binary> [outdir]}"
BIN_AMD64="${2:?missing amd64 binary path}"
BIN_ARM64="${3:?missing arm64 binary path}"
OUT="${4:-out}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$ROOT/packaging/nfpm.yaml"
mkdir -p "$OUT"

build_arch() {
  local arch="$1" bin="$2"
  local resolved
  resolved="$(mktemp -t nfpm-XXXXXX.yaml)"
  sed -e "s|\${PKG_ARCH}|$arch|g" \
      -e "s|\${PKG_VERSION}|$VERSION|g" \
      -e "s|\${PKG_BIN}|$bin|g" \
      -e "s|\${PKG_LICENSE}|$ROOT/LICENSE|g" \
      "$TEMPLATE" > "$resolved"
  nfpm package -f "$resolved" -p deb -t "$OUT/"
  nfpm package -f "$resolved" -p rpm -t "$OUT/"
  rm -f "$resolved"
}

build_arch amd64 "$BIN_AMD64"
build_arch arm64 "$BIN_ARM64"

echo "built packages in $OUT/:"
ls -1 "$OUT"/*.deb "$OUT"/*.rpm
