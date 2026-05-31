#!/usr/bin/env bash
# Cross-compile pgp-sync for the deployment target (linux/amd64 by default).
# Output is a static-ish single binary at ./bin/pgp-sync-linux-amd64.

set -euo pipefail
cd "$(dirname "$0")/.."

OS="${GOOS:-linux}"
ARCH="${GOARCH:-amd64}"
OUT="bin/pgp-sync-${OS}-${ARCH}"

mkdir -p bin
# CGO is off — modernc.org/sqlite is pure Go, so we can cross-compile without
# a C toolchain.
CGO_ENABLED=0 GOOS="$OS" GOARCH="$ARCH" \
  go build -trimpath -ldflags="-s -w" -o "$OUT" ./cmd/pgp-sync

echo "built: $OUT ($(du -h "$OUT" | cut -f1))"
file "$OUT" 2>/dev/null || true
