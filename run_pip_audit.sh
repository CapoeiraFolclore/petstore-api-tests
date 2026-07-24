#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required but was not found on PATH."
  exit 1
fi

PYTHON_VERSION="$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')"
PYTHON_MINOR="$(python3 -c 'import sys; print(sys.version_info.minor)')"
if [[ "${PYTHON_MINOR}" -lt 10 ]]; then
  echo "Python 3.10+ is required for patched dependencies (current: ${PYTHON_VERSION})."
  echo "Install from https://www.python.org/downloads/ or use pyenv/brew, then recreate .venv:"
  echo "  rm -rf .venv && python3.10 -m venv .venv"
  exit 1
fi

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source ".venv/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if [[ -f requirements-dev.txt ]]; then
  python -m pip install -r requirements-dev.txt
fi

echo "Running pip-audit against requirements.txt..."
if ! pip-audit -r requirements.txt; then
  echo "pip-audit reported vulnerabilities. Review output above."
  exit 1
fi

echo "Dependency audit passed."
