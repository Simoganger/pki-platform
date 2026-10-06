#!/usr/bin/env bash
# Builds the Lambda packages into lambda/dist/ (consumed by Terraform archive_file).
#
# The distributor vendors `cryptography`, a compiled library: the wheel MUST
# match the Lambda runtime (python3.13, x86_64, manylinux). We download the
# binary wheel for that platform explicitly, so this works on macOS too.
#
# Run from the repository root:  ./lambda/build.sh   (or: make lambda-build)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DIST="$ROOT/dist"
PYVER="3.13"
PLATFORM="manylinux2014_x86_64"

rm -rf "$DIST"
mkdir -p "$DIST/acm_renewal_distributor"

cp "$ROOT/acm_renewal_distributor/handler.py" "$DIST/acm_renewal_distributor/"
python3 -m pip install \
  --quiet \
  --no-compile \
  --target "$DIST/acm_renewal_distributor" \
  --platform "$PLATFORM" \
  --implementation cp \
  --python-version "$PYVER" \
  --only-binary=:all: \
  -r "$ROOT/acm_renewal_distributor/requirements.txt"

# Remove files that change on every build so archive_file hashes stay stable.
find "$DIST" -name "__pycache__" -type d -prune -exec rm -rf {} +
find "$DIST" -name "*.dist-info" -type d -exec sh -c 'rm -f "$1/RECORD" "$1/INSTALLER"' _ {} \;
find "$DIST" -exec touch -t 202001010000 {} +

echo "Built: $DIST/acm_renewal_distributor ($(du -sh "$DIST/acm_renewal_distributor" | cut -f1))"
