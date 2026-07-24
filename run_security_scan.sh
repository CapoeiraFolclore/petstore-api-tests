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
  echo "Python 3.10+ is required for patched dependencies and pip-audit (current: ${PYTHON_VERSION})."
  echo "Install from https://www.python.org/downloads/ or use pyenv/brew, then recreate .venv:"
  echo "  rm -rf .venv && python3.10 -m venv .venv"
  exit 1
fi

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source ".venv/bin/activate"

python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt >/dev/null
if [[ -f requirements-dev.txt ]]; then
  python -m pip install -r requirements-dev.txt >/dev/null
fi

export PYTHONPATH="${ROOT_DIR}${PYTHONPATH:+:${PYTHONPATH}}"

echo "Running default security scan: Scan this project for security concerns"
set +e
python -m api_tests.security_scan --project-root "$ROOT_DIR" --write-preview "$@"
STATIC_SCAN_EXIT=$?
set -e

echo
echo "Running dependency audit: pip-audit -r requirements.txt"
if ! pip-audit -r requirements.txt; then
  echo "pip-audit reported vulnerabilities. Review output above."
  exit 1
fi

echo "Dependency audit passed."
exit "${STATIC_SCAN_EXIT}"
