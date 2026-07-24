"""Shared pytest fixtures for PetStore API tests."""

from __future__ import annotations

import os
from typing import Any, Dict, Generator

import pytest

from api_tests.config import ApiConfig, load_config
from api_tests.http_client import ApiClient
from api_tests.logging_setup import setup_logging
from api_tests.validators import load_swagger_spec


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--env",
        action="store",
        default=os.getenv("API_ENV", "dev"),
        help="Target environment config to load (dev, staging, prod)",
    )
    parser.addoption(
        "--api-log-level",
        action="store",
        default=os.getenv("API_LOG_LEVEL", "INFO"),
        help="Logging level for HTTP request/response output",
    )


def pytest_configure(config: pytest.Config) -> None:
    setup_logging(config.getoption("--api-log-level"))
    env = config.getoption("--env")
    os.environ["API_ENV"] = env


@pytest.fixture(scope="session")
def api_config(pytestconfig: pytest.Config) -> ApiConfig:
    return load_config(environment=pytestconfig.getoption("--env"))


@pytest.fixture(scope="session")
def api_client(api_config: ApiConfig) -> ApiClient:
    return ApiClient(api_config)


@pytest.fixture(scope="session")
def swagger_spec() -> Dict[str, Any]:
    return load_swagger_spec()


@pytest.fixture(autouse=True)
def _report_test_environment(request: pytest.FixtureRequest, api_config: ApiConfig) -> Generator[None, None, None]:
    """Attach environment metadata to each test for clearer reporting."""
    request.node.user_properties.append(("environment", api_config.environment))
    request.node.user_properties.append(("base_url", api_config.base_url_normalized))
    yield
