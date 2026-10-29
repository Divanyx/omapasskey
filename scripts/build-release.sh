#!/usr/bin/env bash
# Builds the release binaries reproducibly into dist/ and prints their
# SHA-256 sums. The same toolchain and flags give byte-identical files on any
# machine; CI rebuilds every tag and refuses to publish if they differ from
# setup/SHA256SUMS.
set -euo pipefail
cd "$(dirname "$0")/.."
version="$(sed -n 's/^VERSION="\(.*\)"$/\1/p' setup/omapasskey-setup)"
[[ -n $version ]] || { echo "no VERSION in setup/omapasskey-setup" >&2; exit 1; }
want_go="$(sed -n 's/^toolchain go//p' go.mod)"
have_go="$(go env GOVERSION)"
[[ $have_go == "go$want_go" ]] || echo "warning: go.mod pins go$want_go, building with $have_go" >&2
rm -rf dist && mkdir dist
for arch in amd64 arm64; do
  for cmd in omapasskeyd omapasskey; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOFLAGS=-mod=readonly \
      go build -trimpath -buildvcs=false \
      -ldflags "-s -w -buildid= -X main.version=$version" \
      -o "dist/$cmd-linux-$arch" "./cmd/$cmd"
  done
done
(cd dist && sha256sum -- * | sort -k2)
