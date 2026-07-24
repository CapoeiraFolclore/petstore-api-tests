"""PetStore pet endpoint tests."""

from __future__ import annotations

import pytest

from api_tests.http_client import ApiClient
from api_tests.validators import (
    get_definition_schema,
    validate_json_schema,
    validate_status_code,
    validate_swagger_definition,
)


@pytest.mark.smoke
@pytest.mark.pet
def test_get_pet_by_id_returns_valid_pet(api_client: ApiClient, swagger_spec: dict) -> None:
    """GET /pet/{petId} should return a Pet matching the swagger schema."""
    available_response = api_client.get("/pet/findByStatus", params={"status": "available"})
    validate_status_code(available_response, 200)

    pets = available_response.json()
    if not pets:
        pytest.skip("No available pets returned from PetStore API")

    pet_id = pets[0]["id"]
    response = api_client.get(f"/pet/{pet_id}")

    validate_status_code(response, 200)
    body = validate_swagger_definition(response, "Pet", spec=swagger_spec)

    assert isinstance(body.get("name"), str)
    assert isinstance(body.get("photoUrls"), list)
    assert body.get("id") == pet_id


@pytest.mark.pet
def test_find_pets_by_status_available(api_client: ApiClient, swagger_spec: dict) -> None:
    """GET /pet/findByStatus?status=available should return available pets."""
    response = api_client.get("/pet/findByStatus", params={"status": "available"})

    validate_status_code(response, 200)
    pets = response.json()
    assert isinstance(pets, list)

    pet_schema = get_definition_schema(swagger_spec, "Pet")
    array_schema = {"type": "array", "items": pet_schema}
    validate_json_schema(pets, array_schema, spec=swagger_spec)

    for pet in pets[:5]:
        assert pet.get("status") in (None, "available")


@pytest.mark.pet
def test_get_pet_not_found_returns_404(api_client: ApiClient) -> None:
    """GET /pet/{petId} with an invalid ID should return 404."""
    response = api_client.get("/pet/999999999")

    validate_status_code(response, 404)
