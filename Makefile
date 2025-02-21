# Makefile for Microsoft 365 Threat Model Generator

.PHONY: all clean install test lint format coverage security-check docker-build docker-run help dev-setup summary-test

# Default target
all: clean install test lint

# Clean build artifacts and caches
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Install package
install:
	pip install -e .

# Install development dependencies
dev-setup:
	pip install -e ".[dev]"

# Run tests
test:
	pytest src/tests/ -v --cov=threat_model

# Run summary feature tests
summary-test:
	pytest src/tests/test_summary_processor.py -v --cov=threat_model.core.summary_processor

# Run linting
lint:
	pylint src/
	mypy src/
	black --check src/

# Format code
format:
	black src/

# Generate coverage report
coverage:
	pytest --cov=threat_model --cov-report=html src/tests/

# Run security checks
security-check:
	bandit -r src/
	safety check

# Build Docker image
docker-build:
	docker build -t threat-model-generator .

# Run Docker container
docker-run:
	docker run -it --rm \
		-v $(PWD)/src:/workspace/src \
		-v $(PWD)/tests:/workspace/tests \
		-v $(PWD)/data:/workspace/data \
		-v $(PWD)/output:/workspace/output \
		threat-model-generator

# Run summary generation
summary:
	python -m threat_model --summary-output summary.yaml --batch

# Run summary generation with custom input
summary-custom:
	python -m threat_model --summary-output summary.yaml --batch \
		--input-path $(INPUT) \
		--max-length $(MAX_LENGTH)

# Help target
help:
	@echo "Available targets:"
	@echo "  all              : Clean, install, test, and lint"
	@echo "  clean            : Remove build artifacts and caches"
	@echo "  install          : Install package"
	@echo "  dev-setup       : Install development dependencies"
	@echo "  test            : Run all tests"
	@echo "  summary-test    : Run summary feature tests"
	@echo "  lint            : Run linting checks"
	@echo "  format          : Format code with black"
	@echo "  coverage        : Generate coverage report"
	@echo "  security-check  : Run security checks"
	@echo "  docker-build    : Build Docker image"
	@echo "  docker-run      : Run Docker container"
	@echo "  summary         : Run summary generation"
	@echo "  summary-custom  : Run summary with custom input"
	@echo ""
	@echo "Example usage:"
	@echo "  make summary-custom INPUT=input.txt MAX_LENGTH=2000"
