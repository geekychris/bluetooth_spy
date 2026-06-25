#!/usr/bin/env bash
# Run the bt-spy test suite. Defaults to quiet mode.
#
# Usage:
#   ./scripts/run-tests.sh                        # quiet pytest
#   ./scripts/run-tests.sh -v                     # verbose
#   ./scripts/run-tests.sh tests/test_db.py       # single file
#   ./scripts/run-tests.sh -k checksum            # by keyword

set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .venv/bin/pytest ]; then
  echo "Setting up venv first…"
  ./scripts/install.sh
fi

exec .venv/bin/pytest "$@"
