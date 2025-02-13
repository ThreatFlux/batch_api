# Makefile for Microsoft 365 Threat Model Generator

# Variables
PYTHON := python3
PIP := pip3
PYTEST := pytest
PYLINT := pylint
BLACK := black
DOCKER := docker
IMAGE_NAME := threat-model-generator
IMAGE_TAG := latest

# Python settings
VENV := venv
PYTHON_VERSION := 3.13
SRC_DIR := src
TEST_DIR := tests

.PHONY: all clean install test lint format docker-build docker-run help

# Default target
all: clean install test lint

# Create virtual environment
$(VENV)/bin/activate:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -e ".[dev]"

# Install dependencies
install: $(VENV)/bin/activate

# Clean up build artifacts and test results
clean:
	rm -rf $(VENV)
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf test-results.xml
	rm -rf junit/
	rm -rf .mypy_cache/
	rm -rf reports/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type f -name "coverage.xml" -delete
	find . -type f -name "test-results.xml" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +

# Run fast tests (no coverage) for quick feedback
test: install
	$(VENV)/bin/pytest tests/ -v

# Run linting and type checking
lint: install
	$(VENV)/bin/pylint $(SRC_DIR) $(TEST_DIR) --output-format=parseable --reports=yes
	$(VENV)/bin/mypy $(SRC_DIR) --show-error-codes --pretty

# Format code
format: install
	$(VENV)/bin/black $(SRC_DIR) $(TEST_DIR)

# Build Docker image
docker-build:
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) .

# Run Docker container with default settings
docker-run:
	$(DOCKER) run --rm -it \
		-v $(PWD):/app/data \
		-v $(PWD)/output:/app/output \
		--env-file .env \
		$(IMAGE_NAME):$(IMAGE_TAG) \
		--mitre-path office_suite_description_mitre_dump.csv \
		--idp-path idp_description_mitre_dump.csv \
		--audit-path audit_operations.csv \
		--output threat_model.md \
		--batch

# Development setup
dev-setup: install
	$(VENV)/bin/pre-commit install

# Run the application with default settings
run: install
	$(VENV)/bin/python -m threat_model \
		--mitre-path office_suite_description_mitre_dump.csv \
		--idp-path idp_description_mitre_dump.csv \
		--audit-path audit_operations.csv \
		--output threat_model.md \
		--batch

# Run with custom batch processing
run-batch: install
	$(VENV)/bin/python -m threat_model \
		--mitre-path office_suite_description_mitre_dump.csv \
		--idp-path idp_description_mitre_dump.csv \
		--audit-path audit_operations.csv \
		--output threat_model.md \
		--batch \
		--sections "Authentication" "Data Access"

# Generate coverage report
coverage: test
	$(VENV)/bin/coverage html
	$(VENV)/bin/coverage report

# Security check
security-check: install
	bandit -r $(SRC_DIR)
	safety scan

# Type checking
type-check: install
	$(VENV)/bin/mypy $(SRC_DIR)

# Build distribution
dist: clean install
	$(VENV)/bin/python setup.py sdist bdist_wheel

# Show help
help:
	@echo "Available targets:"
	@echo ""
	@echo "Development workflow:"
	@echo "  dev           : Format, lint, and test code"
	@echo "  dev-setup    : Setup development environment"
	@echo "  format       : Format code with black"
	@echo ""
	@echo "Testing:"
	@echo "  test         : Run tests with parallel execution and full reporting"
	@echo "  coverage     : Generate detailed coverage reports"
	@echo ""
	@echo "Code quality:"
	@echo "  lint         : Run linting and type checking with detailed reports"
	@echo "  type-check   : Run MyPy type checking"
	@echo "  security-check: Run security audits (bandit & safety)"
	@echo ""
	@echo "Application:"
	@echo "  run          : Run the application with default settings"
	@echo "  run-batch    : Run batch processing with sections"
	@echo ""
	@echo "Build & Deploy:"
	@echo "  all          : Clean, install, test, and lint"
	@echo "  clean        : Remove build artifacts and caches"
	@echo "  install      : Install dependencies in virtual environment"
	@echo "  docker-build : Build Docker image"
	@echo "  docker-run   : Run Docker container"
	@echo "  dist         : Build distribution packages"

# CI targets
ci-test: install test lint type-check security-check

# Development workflow targets
dev: format lint test

# Production build targets
prod: clean test docker-build

# Default target
.DEFAULT_GOAL := help
