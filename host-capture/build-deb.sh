#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PACKAGE_DIR="$SCRIPT_DIR/package"
OUTPUT=${1:-/tmp/traffic-guardian-host-capture_1.0.0_all.deb}

chmod 0755 \
	"$PACKAGE_DIR/DEBIAN/postinst" \
	"$PACKAGE_DIR/DEBIAN/prerm" \
	"$PACKAGE_DIR/DEBIAN/postrm" \
	"$PACKAGE_DIR/usr/local/sbin/traffic-guardian-capture"

dpkg-deb --root-owner-group --build "$PACKAGE_DIR" "$OUTPUT"
printf 'Built %s\n' "$OUTPUT"
