#!/usr/bin/env bash
# Build sdist + wheel artifacts for bt-spy.
#
# Output: dist/bt_spy-X.Y.Z.tar.gz and dist/bt_spy-X.Y.Z-py3-none-any.whl
#
# Usage:
#   ./scripts/build.sh           # build sdist + wheel
#   ./scripts/build.sh --clean   # clean dist/ + build/ first

set -euo pipefail

cd "$(dirname "$0")/.."

if [ "${1:-}" = "--clean" ]; then
  echo "→ Removing dist/ and build/"
  rm -rf dist build src/bt_spy.egg-info
fi

# Make sure venv exists
if [ ! -d .venv ]; then
  echo "→ Setting up venv (running scripts/install.sh first)"
  ./scripts/install.sh
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "→ Installing build dependency"
pip install --quiet --upgrade build

echo "→ Building sdist + wheel"
python -m build

echo
echo "✓ Built. Artifacts in dist/:"
ls -lh dist/

echo
cat <<EOF
To install from the wheel locally:
  pip install dist/bt_spy-*.whl

To publish to PyPI (when ready):
  pip install --upgrade twine
  twine check dist/*
  twine upload dist/*
EOF
