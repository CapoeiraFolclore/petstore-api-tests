.PHONY: install test test-dev test-staging test-prod clean

install:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -r requirements.txt

test:
	API_ENV=dev PYTHONPATH=. .venv/bin/pytest

test-dev:
	API_ENV=dev PYTHONPATH=. .venv/bin/pytest

test-staging:
	API_ENV=staging PYTHONPATH=. .venv/bin/pytest

test-prod:
	API_ENV=prod PYTHONPATH=. .venv/bin/pytest

clean:
	rm -rf .venv .pytest_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
