.PHONY: run test lint format check install clean publish-live publish-test coverage

run:
	@uv run kseal || true

test:
	@uv run pytest

coverage:
	@uv run pytest --cov=kseal --cov-report=term-missing --cov-report=html

lint:
	@uv run ruff check .

format:
	@uv run ruff format .
	@uv run ruff check --fix .

check: lint test

install:
	@uv sync

clean:
	@rm -rf .venv dist build *.egg-info .pytest_cache .ruff_cache __pycache__ htmlcov .coverage
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true

publish-live:
	@uv build
	@uv publish

publish-test:	
	@uv publish --repository testpypi
