.PHONY: install install-dev check-install format lint test security audit demo validate-go validate-rust validate-python validate validate-local docker-build docker-test docker-demo docker-validate

install: install-dev

install-dev:
	python -m pip install --upgrade pip
	python -m pip install -r requirements-dev.txt
	python -m pip install -e .

check-install:
	python -c "from rygnal import Rygnal; assert Rygnal is not None; print('Rygnal import OK')"
	rygnal --help > /dev/null
	rygnal version
	rygnal policy validate policies/default_policy.yaml

format:
	ruff format src tests demo examples

lint:
	ruff check src tests demo examples

test:
	pytest -q

security:
	bandit -r src demo examples -c pyproject.toml

audit:
	pip-audit -r requirements-dev.txt

demo:
	python -m demo.run_demo

validate-go:
	@echo "==> Validating Go (CLI)..."
	go fmt ./...
	go vet ./...
	go test ./...

validate-rust:
	@echo "==> Validating Rust (Kernel)..."
	cd rust-kernel && cargo fmt --check
	cd rust-kernel && cargo clippy -- -D warnings
	cd rust-kernel && cargo test

validate-python: format lint test security audit demo
	@echo "==> Python engine checks passed!"

validate: validate-go validate-rust validate-python
	@echo "==> All monorepo checks passed!"

validate-local: validate check-install

docker-build:
	docker compose build

docker-test:
	docker compose run --rm rygnal pytest -q

docker-demo:
	docker compose run --rm rygnal python -m demo.run_demo

docker-validate:
	docker compose run --rm rygnal make validate
