# Needed SHELL since I'm using zsh
SHELL := /bin/bash

ts := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

.PHONY: help
help: ## This help message
	@echo -e "$$(grep -hE '^\S+:.*##' $(MAKEFILE_LIST) | sed -e 's/:.*##\s*/:/' -e 's/^\(.\+\):\(.*\)/\\x1b[36m\1\\x1b[m:\2/' | column -c2 -t -s :)"

.PHONY: build
build: dev-build-packages ## Builds Rust code and checks Python modules
	python -m maturin build

.PHONY: build-release
build-release: dev-build-packages ## Build checks module in release mode
	python -m maturin build --release

.PHONY: install
install: dev-build-packages ## Install checks module into current virtualenv
	python -m maturin develop --release

.PHONY: publish
publish: ## Publish crate on Pypi
	python -m maturin publish

.PHONY: clean
clean: ## Clean up build artifacts
	cargo clean

.PHONY: dev-build-packages
dev-build-packages: ## Install Python development packages for project
	python -m pip install .[build]

.PHONY: dev-test-packages
dev-test-packages: dev-build-packages ## Install Python development packages for project
	python -m pip install .[test]

.PHONY: dev-docs-packages
dev-docs-packages: dev-build-packages ## Install Python development packages for project
	python -m pip install .[docs]

.PHONY: cargo-test
cargo-test: ## Run cargo tests only
	cargo test

.PHONY: cargo-clippy
cargo-clippy: ## Run cargo clippy only
	cargo clippy

.PHONY: test
test: cargo-test dev-test-packages build quicktest ## Intall checks module and run tests

.PHONY: quicktest
quicktest: dev-test-packages ## Run tests on already installed checks module
	python -m pytest --hypothesis-profile default  -n=auto tests/

.PHONY: coverage
coverage: cargo-test dev-test-packages ## Intall checks module and run tests with code coverage[]
	python -m pytest --hypothesis-profile default --cov-report term-missing --cov=checks -n=auto tests/

.PHONY: build-profile
build-profile: ## Builds binary for profiling
	cd profiling && python -m cargo build --release

.PHONY: clean-docs
clean-docs: ## Clean the documentation build folder
	rm -rf docs/build

.PHONY: build-docs
build-docs: dev-docs-packages clean-docs ## Build documentation
	python -m sphinx-build -b html docs/source docs/build

# Setup instructions here:
# https://gist.github.com/dlaehnemann/df31787c41bd50c0fe223df07cf6eb89
.PHONY: profile
profile: OUTPUT_PATH = measurements/flame-$(ts).svg
profile: FLAGS=booleans --iterations 10000
profile: build-profile ## Run perf-based profiling (only works on Linux!)
	perf record --call-graph dwarf,16384 -e cpu-clock -F 997 target/release/profiling $(FLAGS)
	time perf script | stackcollapse-perf.pl | c++filt | flamegraph.pl > $(OUTPUT_PATH)
	@echo "$(OUTPUT_PATH)"
