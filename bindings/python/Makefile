# Needed SHELL since I'm using zsh
SHELL := /bin/bash

ts := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

.PHONY: help
help: ## This help message
	@echo -e "$$(grep -hE '^\S+:.*##' $(MAKEFILE_LIST) | sed -e 's/:.*##\s*/:/' -e 's/^\(.\+\):\(.*\)/\\x1b[36m\1\\x1b[m:\2/' | column -c2 -t -s :)"

.PHONY: build
build: dev-packages ## Builds Rust code and pychecks Python modules
	poetry run maturin build

.PHONY: build-release
build-release: nightly dev-packages ## Build pychecks module in release mode
	poetry run maturin build --release

.PHONY: install
install: dev-packages ## Install pychecks module into current virtualenv
	poetry run maturin develop --release

.PHONY: publish
publish: ## Publish crate on Pypi
	poetry run maturin publish

.PHONY: clean
clean: ## Clean up build artifacts
	cargo clean

.PHONY: dev-packages
dev-packages: ## Install Python development packages for project
	poetry install

.PHONY: cargo-test
cargo-test: ## Run cargo tests only
	cargo test

.PHONY: test
test: cargo-test dev-packages install quicktest ## Intall pychecks module and run tests

.PHONY: quicktest
quicktest: ## Run tests on already installed pychecks module
	poetry run pytest --hypothesis-profile default  -n=auto tests/

.PHONY: coverage
coverage: cargo-test dev-packages install ## Intall pychecks module and run tests with code coverage[]
	poetry run pytest --hypothesis-profile default --cov-report term-missing --cov=pychecks -n=auto tests/

.PHONY: build-profile
build-profile: ## Builds binary for profiling
	cd profiling && poetry run cargo build --release

# Setup instructions here:
# https://gist.github.com/dlaehnemann/df31787c41bd50c0fe223df07cf6eb89
.PHONY: profile
profile: OUTPUT_PATH = measurements/flame-$(ts).svg
profile: FLAGS=booleans --iterations 10000
profile: build-profile ## Run perf-based profiling (only works on Linux!)
	perf record --call-graph dwarf,16384 -e cpu-clock -F 997 target/release/profiling $(FLAGS)
	time perf script | stackcollapse-perf.pl | c++filt | flamegraph.pl > $(OUTPUT_PATH)
	@echo "$(OUTPUT_PATH)"
