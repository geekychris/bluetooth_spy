#!/usr/bin/env bash
# Format + lint with ruff.
#
# Usage:
#   ./scripts/format.sh             # format in place + auto-fix lint
#   ./scripts/format.sh --check     # only check; nonzero exit if changes needed

set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .venv/bin/ruff ]; then
  echo "Setting up venv first…"
  ./scripts/install.sh
fi

if [ "${1:-}" = "--check" ]; then
  .venv/bin/ruff format --check src tests
  .venv/bin/ruff check src tests
else
  .venv/bin/ruff format src tests
  .venv/bin/ruff check --fix src tests
fi
