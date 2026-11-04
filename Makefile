# Shortcuts for common development commands. Each target runs a command that
# is documented in CONTRIBUTING.md; run them from the repository root.
#
# `install`, `test` and `lint` use the Python on your PATH, so activate your
# virtual environment first (`. .venv/bin/activate` after `make dev`).

PYTHON ?= python3
PYTEST_ARGS ?= -n auto --dist loadfile

.DEFAULT_GOAL := help

.PHONY: help install dev test lint

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install Lightwork from source into the active virtual environment
	$(PYTHON) scripts/install_release_cohort.py --core-extra release-runtime,evidence-analysis

dev: ## Create .venv with editable packages and the development tools
	bash .devcontainer/post-create.sh

test: ## Run the test suite the way CI does (override PYTEST_ARGS for a serial or narrower run)
	$(PYTHON) -m pytest -q $(PYTEST_ARGS)

lint: ## Run the pre-push lint and contract gates (scripts/pre-push-lint.sh)
	bash scripts/pre-push-lint.sh
