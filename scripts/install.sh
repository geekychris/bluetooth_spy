#!/usr/bin/env bash
# One-shot installer for bt-spy on macOS.
# Usage:  bash scripts/install.sh

set -euo pipefail

cd "$(dirname "$0")/.."

PY=${PYTHON:-python3}

if ! command -v "$PY" >/dev/null 2>&1; then
  echo "ERROR: python3 not found. Install Python 3.11+ first (brew install python@3.12)." >&2
  exit 1
fi

PY_VER=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
PY_MAJOR=${PY_VER%%.*}
PY_MINOR=${PY_VER##*.}
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
  echo "ERROR: Python 3.11+ required, found $PY_VER" >&2
  exit 1
fi

VENV_DIR="${BT_SPY_VENV:-.venv}"
echo "→ Creating venv at $VENV_DIR"
"$PY" -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

pip install --upgrade pip wheel
pip install -e ".[dev]"

echo
echo "✓ Installed. Run:"
echo "    source $VENV_DIR/bin/activate"
echo "    bt-spy doctor      # check environment"
echo "    bt-spy flash       # flash the dongle (plug it in first)"
echo "    bt-spy serve       # web UI at http://127.0.0.1:8765"
