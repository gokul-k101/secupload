.PHONY: setup lint test test-shared test-server test-client test-proxy clean

setup:
	uv sync --all-packages

lint:
	uv run ruff check shared server client proxy

test: test-shared test-server test-client test-proxy

test-shared:
	uv run pytest shared/tests -q

test-server:
	uv run pytest server/tests -q

test-client:
	uv run pytest client/tests -q

test-proxy:
	uv run pytest proxy/tests -q

clean:
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
