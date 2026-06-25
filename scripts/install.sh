#!/usr/bin/env bash
# One-shot installer for bt-spy on macOS.
#   Creates a venv, pip-installs bt-spy in editable mode, prints next steps.
# Usage:
#   ./scripts/install.sh           # default: venv at .venv/
#   BT_SPY_VENV=~/.venvs/bts ./scripts/install.sh
#   PYTHON=python3.12 ./scripts/install.sh

set -euo pipefail

cd "$(dirname "$0")/.."

PY=${PYTHON:-python3}

if ! command -v "$PY" >/dev/null 2>&1; then
  cat <<EOF >&2
ERROR: python3 not found on PATH.
  brew install python@3.12      # macOS
  apt install python3.12        # Debian/Ubuntu
EOF
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
if [ ! -d "$VENV_DIR" ]; then
  echo "→ Creating venv at $VENV_DIR"
  "$PY" -m venv "$VENV_DIR"
else
  echo "→ Reusing existing venv at $VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "→ Upgrading pip + wheel"
pip install --upgrade --quiet pip wheel

echo "→ Installing bt-spy (editable) + dev extras"
pip install --quiet -e ".[dev]"

cat <<EOF

✓ Installed. Next steps:

    source $VENV_DIR/bin/activate
    bt-spy doctor                 # environment check
    bt-spy serve                  # web UI at http://127.0.0.1:8765

For OTA sniffing you need the nRF52840 dongle + nrfutil 8.x.
See docs/firmware-flashing.md for the modern setup flow.

For Mac-side HCI capture (no hardware): see docs/packetlogger.md.

For Claude integration: add this to your Claude Code config and reload:
    {
      "mcpServers": {
        "bt-spy": { "command": "$VENV_DIR/bin/bt-spy", "args": ["mcp"] }
      }
    }

EOF
