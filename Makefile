.PHONY: install lint typecheck security test check demo clean

install:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

typecheck:
	uv run mypy

security:
	uv run bandit -c pyproject.toml -r app -q
	uv run pip-audit --skip-editable

test:
	uv run pytest

check: lint typecheck security test

demo:
	uv run uvicorn app.main:app --host 127.0.0.1 --port 8000

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
