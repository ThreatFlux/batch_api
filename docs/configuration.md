# Configuration Guide

This guide covers the configuration options for the Microsoft 365 Threat Model Generator.

## Environment Configuration

### Docker Configuration

The Docker image includes several configuration options through labels and environment variables:

```dockerfile
# Environment Variables
ENV PYTHONPATH=/workspace/src

# Metadata Labels
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.authors="wyattroersma@gmail.com"
LABEL org.opencontainers.image.url="https://github.com/ThreatFlux/batch_api"
LABEL org.opencontainers.image.documentation="https://github.com/ThreatFlux/batch_api"
LABEL org.opencontainers.image.source="https://github.com/ThreatFlux/batch_api"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.vendor="ThreatFlux"
LABEL org.opencontainers.image.title="batch_api"
LABEL org.opencontainers.image.description="ThreatFlux Microsoft 365 Threat Model Generator"
```

## Project Structure

```
.
├── src/
│   └── threat_model/
│       ├── core/           # Core implementation
│       ├── prompts/        # Template files
│       └── utils/          # Utility functions
├── tests/                  # Test suite
├── docs/                   # Documentation
├── data/                   # Input data directory
└── output/                 # Generated output
```

## Data Sources

### MITRE ATT&CK Data

The MITRE CSV file should contain:
- Technique ID
- Tactic
- Technique Name
- Description

Example format:
```csv
TID,Tactic,Technique,Description
T1110,Initial Access,Brute Force,Adversaries may attempt to...
```

### Microsoft 365 Audit Data

The audit operations CSV should contain:
- Operation Name
- Friendly Name
- Description

Example format:
```csv
Operation,FriendlyName,Description
Add-MailboxPermission,Add Mailbox Permission,Grants permissions to a mailbox...
```

## Development Configuration

### Make Commands

The project includes several Make targets for development:

```bash
# Clean build artifacts
make clean

# Run tests with coverage
make test

# Run linting checks
make lint

# Format code
make format

# Full CI pipeline
make ci-test
```

### Docker Development

Development stage configuration:
```bash
# Build development image
docker build --target development -t batch-api:dev .

# Run with mounted volumes
docker run -it --rm \
    -v $(pwd)/src:/workspace/src \
    -v $(pwd)/tests:/workspace/tests \
    -v $(pwd)/data:/workspace/data \
    -v $(pwd)/output:/workspace/output \
    batch-api:dev
```

### Testing Configuration

Test settings can be configured through:
- pytest.ini for test configuration
- .coveragerc for coverage settings
- .pylintrc for linting rules

## Production Configuration

### Docker Production

Production stage optimizations:
- Minimal base image
- Only required dependencies
- Health check monitoring
- Environment variable configuration

### Health Check Configuration

The health check can be customized through Docker run flags:
```bash
--health-cmd="python3 -c 'import threat_model; print(\"Health check passed\")'"
--health-interval=30s
--health-timeout=30s
--health-start-period=5s
--health-retries=3
```

## Security Configuration

Security measures include:
- Non-root user (python_builder)
- Minimal permissions
- Regular security audits (make security-check)
- Dependency scanning
