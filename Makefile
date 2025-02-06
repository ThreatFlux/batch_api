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
PYTHON_VERSION := 3.8
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

# Clean up
clean:
	rm -rf $(VENV)
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type f -name "coverage.xml" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +

# Run tests
test: install
	$(VENV)/bin/pytest $(TEST_DIR) -v --cov=$(SRC_DIR) --cov-report=term-missing

# Run linting
lint: install
	$(VENV)/bin/pylint $(SRC_DIR) $(TEST_DIR)
	$(VENV)/bin/mypy $(SRC_DIR)

# Format code
format: install
	$(VENV)/bin/black $(SRC_DIR) $(TEST_DIR)

# Build Docker image
docker-build:
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) .

# Run Docker container
docker-run:
	$(DOCKER) run --rm -it \
		-v $(PWD)/data:/app/data \
		-v $(PWD)/output:/app/output \
		--env-file .env \
		$(IMAGE_NAME):$(IMAGE_TAG)

# Development setup
dev-setup: install
	$(VENV)/bin/pre-commit install

# Run the application
run: install
	$(VENV)/bin/python -m threat_model

# Run batch processing
run-batch: install
	$(VENV)/bin/python -m threat_model --batch

# Generate coverage report
coverage: test
	$(VENV)/bin/coverage html
	$(VENV)/bin/coverage report

# Security check
security-check: install
	$(VENV)/bin/bandit -r $(SRC_DIR)
	$(VENV)/bin/safety check

# Type checking
type-check: install
	$(VENV)/bin/mypy $(SRC_DIR)

# Build distribution
dist: clean install
	$(VENV)/bin/python setup.py sdist bdist_wheel

# Show help
help:
	@echo "Available targets:"
	@echo "  all            : Clean, install, test, and lint"
	@echo "  clean          : Remove build artifacts and caches"
	@echo "  install        : Install dependencies in virtual environment"
	@echo "  test           : Run tests with coverage"
	@echo "  lint           : Run linting checks"
	@echo "  format         : Format code with black"
	@echo "  docker-build   : Build Docker image"
	@echo "  docker-run     : Run Docker container"
	@echo "  dev-setup     : Setup development environment"
	@echo "  run           : Run the application"
	@echo "  run-batch     : Run batch processing"
	@echo "  coverage      : Generate coverage report"
	@echo "  security-check: Run security checks"
	@echo "  type-check    : Run type checking"
	@echo "  dist          : Build distribution packages"

# CI targets
ci-test: install test lint type-check security-check

# Development workflow targets
dev: format lint test

# Production build targets
prod: clean test docker-build

# Default target
.DEFAULT_GOAL := help