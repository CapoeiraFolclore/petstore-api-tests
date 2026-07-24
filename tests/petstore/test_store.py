"""PetStore store endpoint tests."""

from __future__ import annotations

import pytest

from api_tests.http_client import ApiClient
from api_tests.models import Order
from api_tests.validators import (
    validate_header,
    validate_json_body_fields,
    validate_status_code,
    validate_swagger_definition,
)


@pytest.mark.smoke
@pytest.mark.store
def test_get_store_inventory_returns_status_counts(
    api_client: ApiClient,
    swagger_spec: dict,
) -> None:
    """GET /store/inventory should return a map of status codes to quantities."""
    response = api_client.get("/store/inventory")

    validate_status_code(response, 200)
    validate_header(response, "content-type", present=True)

    inventory = response.json()
    assert isinstance(inventory, dict)
    assert inventory, "Expected at least one inventory bucket"

    for status_name, quantity in inventory.items():
        assert isinstance(status_name, str)
        assert isinstance(quantity, int)
        assert quantity >= 0


@pytest.mark.store
def test_get_order_by_id_returns_valid_order(api_client: ApiClient, swagger_spec: dict) -> None:
    """POST then GET /store/order/{orderId} should return a valid Order."""
    create_response = api_client.post(
        "/store/order",
        json_body=Order(pet_id=1, quantity=1, status="placed", complete=False).to_json(),
    )
    validate_status_code(create_response, 200)
    created_order = validate_swagger_definition(create_response, "Order", spec=swagger_spec)
    order_id = created_order["id"]

    response = api_client.get(f"/store/order/{order_id}")

    validate_status_code(response, 200)
    body = validate_swagger_definition(response, "Order", spec=swagger_spec)

    validate_json_body_fields(response, {"id": order_id})
    assert body["petId"] == 1
    assert body["quantity"] == 1
    assert body["status"] == "placed"
    assert body["complete"] is False


@pytest.mark.store
def test_place_order_returns_created_order(api_client: ApiClient, swagger_spec: dict) -> None:
    """POST /store/order should create an order and return 200 with an Order body."""
    order = Order(pet_id=1, quantity=1, status="placed", complete=False)
    response = api_client.post("/store/order", json_body=order.to_json())

    validate_status_code(response, 200)
    body = validate_swagger_definition(response, "Order", spec=swagger_spec)

    assert body["petId"] == 1
    assert body["quantity"] == 1
    assert body["status"] == "placed"
    assert body["complete"] is False
