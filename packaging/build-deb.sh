#!/usr/bin/env bash
# Builds server-sentinel_<version>_amd64.deb from a release binary.
# Usage: packaging/build-deb.sh
# Requires: cargo, dpkg-deb. Run from the repo root.
set -euo pipefail

VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d '"' -f2)
ROOT="$(pwd)"
PKGROOT="$ROOT/pkg/deb/server-sentinel_${VERSION}_amd64"

echo "==> Building release binary"
cargo build --release

echo "==> Staging package tree for version $VERSION"
rm -rf "$ROOT/pkg/deb"
mkdir -p "$PKGROOT"/{DEBIAN,usr/bin,etc/server-sentinel,lib/systemd/system,var/lib/server-sentinel/incidents,var/lib/server-sentinel/reports}

cp "$ROOT/target/release/server-sentinel" "$PKGROOT/usr/bin/server-sentinel"
chmod 755 "$PKGROOT/usr/bin/server-sentinel"
cp "$ROOT/packaging/common/server-sentinel.toml" "$PKGROOT/etc/server-sentinel/server-sentinel.toml"
cp "$ROOT/packaging/common/server-sentinel.service" "$PKGROOT/lib/systemd/system/server-sentinel.service"

INSTALLED_SIZE=$(du -sk --exclude=DEBIAN "$PKGROOT" | cut -f1)

cat > "$PKGROOT/DEBIAN/control" << EOF
Package: server-sentinel
Version: ${VERSION}-1
Section: admin
Priority: optional
Architecture: amd64
Installed-Size: ${INSTALLED_SIZE}
Maintainer: ServerSentinel <support@example.com>
Depends: libc6 (>= 2.34)
Description: Automated infrastructure incident investigation agent
 ServerSentinel watches CPU, memory and disk on a Linux server. When a
 resource sustains a critical level, it automatically switches into a
 fast-sampling investigation mode, correlates the responsible process,
 scores a confident root cause, and writes a JSON + HTML incident report
 with no manual triage required.
 .
 Config: /etc/server-sentinel/server-sentinel.toml
 Reports: /var/lib/server-sentinel/{incidents,reports}
EOF

cp "$ROOT/packaging/common/postinst" "$PKGROOT/DEBIAN/postinst"
cp "$ROOT/packaging/common/prerm" "$PKGROOT/DEBIAN/prerm"
cp "$ROOT/packaging/common/postrm" "$PKGROOT/DEBIAN/postrm"
printf '/etc/server-sentinel/server-sentinel.toml\n' > "$PKGROOT/DEBIAN/conffiles"
chmod 755 "$PKGROOT/DEBIAN/postinst" "$PKGROOT/DEBIAN/prerm" "$PKGROOT/DEBIAN/postrm"

echo "==> Building .deb"
dpkg-deb --root-owner-group --build "$PKGROOT"
echo "==> Built: pkg/deb/server-sentinel_${VERSION}_amd64.deb"
