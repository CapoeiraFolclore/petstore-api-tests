# PetStore API Tests

Python/pytest API test suite for the [Swagger Petstore](https://petstore.swagger.io/) (`/v2` API). Tests make real HTTP requests, validate status codes, headers, response fields, and swagger-derived JSON schemas, and produce clear pass/fail output via pytest.

## Requirements

- Python 3.9+ (Python 3.10+ recommended)
- Network access to `https://petstore.swagger.io`

If Python is missing:

```bash
# macOS (Homebrew)
brew install python

# Verify
python3 --version
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

See `PetStore.md` for the original project prompt and agent conversation transcript.
