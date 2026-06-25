#!/usr/bin/env bash
# Full dev environment bootstrap for bt-spy contributors.
#
# What this does on top of install.sh:
#   - Installs nrfutil 8.x via brew (where available)
#   - Installs pre-commit hook (ruff format + pytest)
#   - Generates dev shortcuts in .env.dev
#
# Usage:
#   ./scripts/dev-setup.sh

set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Step 1/4: Run base install ==="
./scripts/install.sh

echo
echo "=== Step 2/4: Install nrfutil 8.x (Nordic) ==="
if command -v brew >/dev/null 2>&1; then
  # Note: brew installs the legacy Python nrfutil. The new Nordic standalone
  # binary is not on Homebrew. We warn the user.
  if ! brew list nrfutil >/dev/null 2>&1; then
    echo "(Skipping brew install — the brew formula is the OLD Python nrfutil 6.x."
    echo " You want the new Nordic 8.x binary from"
    echo "   https://www.nordicsemi.com/Products/Development-tools/nRF-Util/Download"
    echo " See docs/firmware-flashing.md for installation steps.)"
  fi
else
  echo "(brew not available; skipping)"
fi

echo
echo "=== Step 3/4: Install pre-commit hook ==="
HOOK_PATH=".git/hooks/pre-commit"
if [ -d ".git" ]; then
  cat > "$HOOK_PATH" <<'HOOK'
#!/usr/bin/env bash
# bt-spy pre-commit: format check + tests.
set -e
echo "→ ruff format check"
.venv/bin/ruff format --check src tests || {
  echo "  (run: ./scripts/format.sh)"; exit 1; }
echo "→ pytest"
.venv/bin/pytest -q
HOOK
  chmod +x "$HOOK_PATH"
  echo "  Installed $HOOK_PATH"
else
  echo "  (not a git repo; skipping)"
fi

echo
echo "=== Step 4/4: Write .env.dev ==="
cat > .env.dev <<EOF
# Dev environment overrides — source this in your shell:
#   source .env.dev
export BTSPY_DATA_DIR=\$PWD/dev-data
export BTSPY_LOG_LEVEL=DEBUG
export BTSPY_REST_PORT=8765
EOF

cat <<EOF

✓ Dev setup complete.

Suggested workflow:
  source .venv/bin/activate
  source .env.dev
  ./scripts/run-tests.sh           # quick test run
  ./scripts/format.sh              # ruff format + fix
  bt-spy serve                     # web UI

Pre-commit hook installed at .git/hooks/pre-commit:
  on every git commit it runs:
    - ruff format --check
    - pytest

To bypass occasionally:  git commit --no-verify  (please don't make a habit of it)

EOF
