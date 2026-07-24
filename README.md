# PetStore API Tests

Python/pytest API test suite for the [Swagger Petstore](https://petstore.swagger.io/) (`/v2` API). Tests make real HTTP requests, validate status codes, headers, response fields, and swagger-derived JSON schemas, and produce clear pass/fail output via pytest.

## Requirements

- **Python 3.10+** (required for patched dependency versions)
- Network access to `https://petstore.swagger.io`

If Python is missing or outdated:

```bash
# Verify version (must be 3.10+)
python3 --version

# Install from https://www.python.org/downloads/
# Then recreate the virtual environment:
rm -rf .venv
python3 -m venv .venv
```

## Quick start

Run everything with a single command:

```bash
chmod +x run_tests.sh
./run_tests.sh
```

Or with Make after creating a virtual environment:

```bash
make install
make test
```

## Project layout

```
petstore-api-tests/
├── api_tests/              # Shared test framework code
│   ├── config.py           # Environment-based configuration loader
│   ├── http_client.py      # HTTP client with request/response logging
│   ├── validators.py       # Status, header, field, and schema validators
│   └── models.py           # PetStore models from swagger definitions
├── config/                 # Per-environment settings (dev/staging/prod)
├── specs/
│   └── petstore.swagger.json
├── tests/
│   ├── conftest.py         # Pytest fixtures
│   └── petstore/           # Example API tests
├── run_tests.sh            # One-command test runner
├── run_security_scan.sh    # Default security scan command
├── pytest.ini
└── requirements.txt
```

## Environment configuration

Set the target environment without changing test code:

```bash
# Default
API_ENV=dev ./run_tests.sh

# Staging / prod configs
API_ENV=staging ./run_tests.sh
API_ENV=prod ./run_tests.sh
```

Optional overrides via `.env` (copy from `.env.example`):

```bash
API_ENV=dev
API_BASE_URL=https://petstore.swagger.io/v2
API_TIMEOUT=30
```

Configuration files live in `config/<env>.yaml` and support:

- `base_url` — API root URL
- `timeout` — request timeout in seconds
- `verify_ssl` — TLS certificate verification
- `default_headers` — headers sent on every request
- `auth` — optional auth headers (unused for PetStore; no authentication required)

## Running tests

```bash
# All tests (default environment: dev)
./run_tests.sh

# Choose environment via pytest flag
./run_tests.sh --env staging

# Filter by marker
./run_tests.sh -m smoke

# Increase HTTP logging detail
./run_tests.sh --api-log-level DEBUG
```

## Security scan (default)

Run the built-in **"Scan this project for security concerns"** check. This runs static analysis (SEC-001 – SEC-012) mapped to **OWASP Top 10**, **ISO/IEC 27001 Annex A**, and **NIST CSF**, then **`pip-audit -r requirements.txt`** for known dependency CVEs.

```bash
chmod +x run_security_scan.sh
./run_security_scan.sh
```

**Cursor Preview tab:** Open `api_tests/security_scan.preview.md` or the generated `api_tests/security_scan.report.md` and select **Preview** in the tab bar (Markdown files get Preview alongside Code and Blame; Python files do not).

JSON output for CI:

```bash
./run_security_scan.sh --format json
```

Or with Make:

```bash
make security-scan
```

Programmatic usage:

```python
from api_tests.security_scan import scan_project_for_security_concerns, print_security_scan_report

report = scan_project_for_security_concerns()
print_security_scan_report(report)
```

The scanner checks for hardcoded secrets, dangerous code patterns, sensitive logging, TLS settings, and other common project security issues. It prints a pass/fail report with severity, location, and finding details.

## Dependency audit (pip-audit)

The default `./run_security_scan.sh` already runs `pip-audit -r requirements.txt` after the static scan.

To run the dependency audit only:

```bash
chmod +x run_pip_audit.sh
./run_pip_audit.sh
```

Recent advisories required bumping minimum versions in `requirements.txt` (pytest, requests, python-dotenv, urllib3). Those patched releases require **Python 3.10+**.

## Validation features

The framework validates:

| Check | Helper |
|-------|--------|
| HTTP status code | `validate_status_code()` |
| Response headers | `validate_header()` |
| Specific JSON field values | `validate_json_body_fields()` |
| Swagger definition schema | `validate_swagger_definition()` |
| Arbitrary JSON schema | `validate_json_schema()` |

HTTP requests and responses are logged at `INFO` level through the shared `ApiClient`.

## Example test pattern

```python
def test_get_pet_by_id_returns_valid_pet(api_client, swagger_spec):
    response = api_client.get("/pet/1")

    validate_status_code(response, 200)
    body = validate_swagger_definition(response, "Pet", spec=swagger_spec)

    assert body["id"] == 1
```

## API source

OpenAPI/Swagger definition: https://petstore.swagger.io/v2/swagger.json

Target host: `petstore.swagger.io` · base path: `/v2` · no authentication required for the example tests.

## Documentation

- `PetStore.md` — original project prompt and agent conversation transcript
- `docs/SECURITY_GUIDELINES.md` — OWASP / ISO 27001 / NIST secure coding baseline
- `docs/SECURITY_REVIEW_PROMPT.md` — copy/paste prompts for scans and reviews
- `.cursor/skills/secure-code-generation/Security_SKILL.md` — agent skill for secure code generation
