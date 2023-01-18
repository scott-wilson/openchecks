# Needed SHELL since I'm using zsh
SHELL := /bin/bash

ts := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

.PHONY: help
help: ## This help message
	@echo -e "$$(grep -hE '^\S+:.*##' $(MAKEFILE_LIST) | sed -e 's/:.*##\s*/:/' -e 's/^\(.\+\):\(.*\)/\\x1b[36m\1\\x1b[m:\2/' | column -c2 -t -s :)"

.PHONY: dev-packages
dev-packages: ## Install Python development packages for project
	poetry install

.PHONY: test
test: dev-packages quicktest ## Intall pychecks module and run tests

.PHONY: quicktest
quicktest: ## Run tests on already installed pychecks module
	poetry run pytest --hypothesis-profile default  -n=auto tests/

.PHONY: coverage
coverage: dev-packages ## Intall pychecks module and run tests with code coverage[]
	poetry run pytest --hypothesis-profile default --cov-report term-missing --cov=pychecks -n=auto tests/

.PHONY: clean-docs
clean-docs: ## Clean the documentation build folder
	rm -rf docs/build

.PHONY: build-docs
build-docs: dev-packages clean-docs ## Build documentation
	poetry run sphinx-build -b html docs/source docs/build
