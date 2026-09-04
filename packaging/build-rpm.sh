#!/usr/bin/env bash
# Builds server-sentinel-<version>-1.x86_64.rpm from a release binary.
# Usage: packaging/build-rpm.sh
# Requires: cargo, rpmbuild (Fedora/RHEL: `dnf install rpm-build`;
# Debian/Ubuntu: `apt install rpm`). Run from the repo root.
set -euo pipefail

VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d '"' -f2)
ROOT="$(pwd)"
RPMBUILD_DIR="$HOME/rpmbuild"

echo "==> Building release binary"
cargo build --release

echo "==> Staging rpmbuild sources for version $VERSION"
mkdir -p "$RPMBUILD_DIR"/{SPECS,SOURCES,BUILD,RPMS,SRPMS,BUILDROOT}
STAGE="/tmp/server-sentinel-${VERSION}"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp "$ROOT/target/release/server-sentinel" "$STAGE/server-sentinel"
cp "$ROOT/packaging/common/server-sentinel.toml" "$STAGE/server-sentinel.toml"
cp "$ROOT/packaging/common/server-sentinel.service" "$STAGE/server-sentinel.service"
tar -C /tmp -czf "$RPMBUILD_DIR/SOURCES/server-sentinel-${VERSION}.tar.gz" "server-sentinel-${VERSION}"

echo "==> Rendering spec file"
sed "s/@VERSION@/${VERSION}/g" "$ROOT/packaging/server-sentinel.spec.in" > "$RPMBUILD_DIR/SPECS/server-sentinel.spec"

echo "==> Building .rpm"
rpmbuild -bb "$RPMBUILD_DIR/SPECS/server-sentinel.spec"

OUT="$RPMBUILD_DIR/RPMS/x86_64/server-sentinel-${VERSION}-1.x86_64.rpm"
mkdir -p "$ROOT/pkg/rpm"
cp "$OUT" "$ROOT/pkg/rpm/"
echo "==> Built: pkg/rpm/server-sentinel-${VERSION}-1.x86_64.rpm"
