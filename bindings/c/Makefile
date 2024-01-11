# TODO: Most of these could probably be moved to CMake

# Needed SHELL since I'm using zsh
SHELL := /bin/bash

ts := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

.PHONY: help
help:
	@echo -e "$$(grep -hE '^\S+:.*##' $(MAKEFILE_LIST) | sed -e 's/:.*##\s*/:/' -e 's/^\(.\+\):\(.*\)/\\x1b[36m\1\\x1b[m:\2/' | column -c2 -t -s :)"

.PHONY: build-dir
build-dir:
	cmake -E make_directory build; cd build

.PHONY: config
config: build-dir
	cmake -S . -B build

.PHONY: build
build: config
	cmake --build build --config=Debug

.PHONY: build-release
build-release: config
	cmake --build build --config=Release

.PHONY: install
install:
	echo "TODO"

.PHONY: clean
clean:
	rm -rf build/

.PHONY: test
test: build
	cd build; ctest

.PHONY: clean-docs
clean-docs:
	rm -rf docs/build

.PHONY: build-docs
build-docs: install clean-docs
	doxygen docs/Doxyfile; python -m sphinx-build -b html docs/source docs/build
