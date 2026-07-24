#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required but was not found on PATH."
  echo "Install Python 3.10+ from https://www.python.org/downloads/ or via Homebrew:"
  echo "  brew install python"
  exit 1
fi

if [[ ! -d ".venv" ]]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source ".venv/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

SWAGGER_FILE="${ROOT_DIR}/specs/petstore.swagger.json"
if [[ ! -f "${SWAGGER_FILE}" ]]; then
  echo "Downloading PetStore swagger spec..."
  curl -sL "https://petstore.swagger.io/v2/swagger.json" -o "${SWAGGER_FILE}"
fi

export API_ENV="${API_ENV:-dev}"
export PYTHONPATH="${ROOT_DIR}${PYTHONPATH:+:${PYTHONPATH}}"

echo "Running PetStore API tests against environment: ${API_ENV}"
python -m pytest "$@"
