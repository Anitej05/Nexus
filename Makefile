.PHONY: bootstrap lint typecheck test-unit test-integration test-contract test-security verify

bootstrap:
	uv sync --all-packages

lint:
	uv run ruff check .

typecheck:
	uv run mypy apps packages

test-unit:
	uv run pytest packages/contracts/tests -q

test-integration:
	docker compose --env-file .env.example -f infrastructure/compose/compose.yml up -d --wait

test-contract:
	uv run pytest tests/contract -q

test-security:
	uv run pip-audit

verify: lint typecheck test-unit test-contract
	uv run python scripts/generate_contracts.py --check
