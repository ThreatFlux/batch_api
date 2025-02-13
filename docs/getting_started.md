# Getting Started Guide

This guide will help you get started with the Microsoft 365 Threat Model Generator.

## Installation Options

### Standard Installation

```bash
# Install package
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"
```

### Docker Installation

The project uses a multi-stage Docker build with three stages:

1. **Builder Stage**
   - Base image: threatflux/python-builder:main
   - Compiles and installs dependencies
   - Optimized for build performance

2. **Development Stage**
   - Includes full source code and test suite
   - Mounted volumes for live development
   - Development dependencies included

3. **Production Stage**
   - Minimal image with only required components
   - Optimized for production deployment
   - Includes health check monitoring

```bash
# Build Docker image
make docker-build

# Run container (production)
make docker-run

# Development with mounted volumes
docker run -it --rm \
    -v $(pwd)/src:/workspace/src \
    -v $(pwd)/tests:/workspace/tests \
    -v $(pwd)/data:/workspace/data \
    -v $(pwd)/output:/workspace/output \
    threatflux/batch-api:latest-dev
```

## Basic Usage

### Command Line Interface

```bash
# Using default CSV files (recommended)
python -m threat_model \
    --mitre-path office_suite_description_mitre_dump.csv \
    --idp-path idp_description_mitre_dump.csv \
    --audit-path audit_operations.csv \
    --output threat_model.md \
    --batch

# Or simply use Make
make run
```

### Python API

```python
from threat_model.core import ThreatModelGenerator

# Initialize generator
generator = ThreatModelGenerator(api_key="your-anthropic-api-key")

# Load data (using default paths)
generator.load_data(
    mitre_path="office_suite_description_mitre_dump.csv",
    idp_path="idp_description_mitre_dump.csv",
    audit_path="audit_operations.csv"
)

# Generate threat model
threat_model = generator.generate_threat_model()
```

## Docker Environment Variables

The following environment variables can be configured:

- `PYTHONPATH`: Set to /workspace/src
- `BUILD_DATE`: Build timestamp
- `VERSION`: Image version

## Health Check

The Docker container includes a health check that runs every 30 seconds:
```bash
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python3 -c "import threat_model; print('Health check passed')" || exit 1
```

## Next Steps

- Read the [Configuration Guide](configuration.md) for customization options
- Explore [Templates Guide](templates.md) for output formatting
- Check [Advanced Usage](advanced_usage.md) for complex features
