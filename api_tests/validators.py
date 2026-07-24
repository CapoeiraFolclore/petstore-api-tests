"""Response validation helpers for API tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Union

import jsonschema
import requests
from jsonschema import Draft4Validator

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SWAGGER_PATH = PROJECT_ROOT / "specs" / "petstore.swagger.json"


class ApiValidationError(AssertionError):
    """Raised when an API response fails validation."""


def load_swagger_spec(path: Optional[Path] = None) -> Dict[str, Any]:
    with (path or SWAGGER_PATH).open(encoding="utf-8") as handle:
        return json.load(handle)


def get_definition_schema(spec: Dict[str, Any], definition_name: str) -> Dict[str, Any]:
    definitions = spec.get("definitions", {})
    if definition_name not in definitions:
        raise KeyError(f"Definition '{definition_name}' not found in swagger spec")
    return definitions[definition_name]


def validate_status_code(
    response: requests.Response,
    expected: Union[int, Iterable[int]],
) -> None:
    expected_codes = {expected} if isinstance(expected, int) else set(expected)
    if response.status_code not in expected_codes:
        raise ApiValidationError(
            f"Expected status {sorted(expected_codes)}, got {response.status_code}. "
            f"Body: {response.text[:500]}"
        )


def validate_header(
    response: requests.Response,
    header_name: str,
    expected_value: Optional[str] = None,
    *,
    present: bool = True,
) -> None:
    header_key = header_name.lower()
    response_headers = {k.lower(): v for k, v in response.headers.items()}

    if present and header_key not in response_headers:
        raise ApiValidationError(f"Expected header '{header_name}' to be present")

    if not present and header_key in response_headers:
        raise ApiValidationError(f"Expected header '{header_name}' to be absent")

    if expected_value is not None and response_headers.get(header_key) != expected_value:
        actual = response_headers.get(header_key)
        raise ApiValidationError(
            f"Header '{header_name}': expected '{expected_value}', got '{actual}'"
        )


def validate_json_body_fields(
    response: requests.Response,
    expected_fields: Mapping[str, Any],
) -> None:
    try:
        body = response.json()
    except ValueError as exc:
        raise ApiValidationError("Response body is not valid JSON") from exc

    for field_name, expected in expected_fields.items():
        if field_name not in body:
            raise ApiValidationError(f"Missing field '{field_name}' in response body")
        actual = body[field_name]
        if actual != expected:
            raise ApiValidationError(
                f"Field '{field_name}': expected {expected!r}, got {actual!r}"
            )


def validate_json_schema(
    payload: Any,
    schema: Mapping[str, Any],
    *,
    spec: Optional[Dict[str, Any]] = None,
) -> None:
    validator = Draft4Validator(schema, resolver=_build_resolver(spec))
    errors = sorted(validator.iter_errors(payload), key=lambda err: err.path)
    if errors:
        messages = "; ".join(error.message for error in errors[:5])
        raise ApiValidationError(f"Schema validation failed: {messages}")


def validate_response_schema(
    response: requests.Response,
    schema: Mapping[str, Any],
    *,
    spec: Optional[Dict[str, Any]] = None,
) -> Any:
    try:
        payload = response.json()
    except ValueError as exc:
        raise ApiValidationError("Response body is not valid JSON") from exc
    validate_json_schema(payload, schema, spec=spec)
    return payload


def validate_swagger_definition(
    response: requests.Response,
    definition_name: str,
    *,
    spec: Optional[Dict[str, Any]] = None,
) -> Any:
    swagger = spec or load_swagger_spec()
    schema = get_definition_schema(swagger, definition_name)
    return validate_response_schema(response, schema, spec=swagger)


def _build_resolver(spec: Optional[Dict[str, Any]]):
    if spec is None:
        return None
    return jsonschema.RefResolver.from_schema(spec)
