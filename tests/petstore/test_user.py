"""PetStore user endpoint tests."""

from __future__ import annotations

import uuid

import pytest

from api_tests.http_client import ApiClient
from api_tests.models import User
from api_tests.validators import (
    validate_json_body_fields,
    validate_status_code,
    validate_swagger_definition,
)


@pytest.mark.smoke
@pytest.mark.user
def test_create_and_get_user_by_name(api_client: ApiClient, swagger_spec: dict) -> None:
    """POST /user then GET /user/{username} should return the created user."""
    username = f"api-test-user-{uuid.uuid4().hex[:8]}"
    user = User(
        username=username,
        first_name="API",
        last_name="Tester",
        email=f"{username}@example.com",
        password="test-password",
        phone="555-0100",
        user_status=1,
    )

    create_response = api_client.post("/user", json_body=user.to_json())
    validate_status_code(create_response, 200)

    response = api_client.get(f"/user/{username}")

    validate_status_code(response, 200)
    body = validate_swagger_definition(response, "User", spec=swagger_spec)

    validate_json_body_fields(response, {"username": username})
    assert body["firstName"] == "API"
    assert body["lastName"] == "Tester"
    assert body["email"] == f"{username}@example.com"


@pytest.mark.user
def test_get_user_not_found_returns_404(api_client: ApiClient) -> None:
    """GET /user/{username} with an unknown user should return 404."""
    response = api_client.get("/user/does-not-exist-xyz-12345")

    validate_status_code(response, 404)
