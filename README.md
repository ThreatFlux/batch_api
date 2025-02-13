# Microsoft 365 Threat Model Generator

A Python package for generating comprehensive threat models for Microsoft 365 and Entra ID environments. The tool analyzes MITRE ATT&CK techniques and Microsoft 365 audit operations to create detailed threat models with detection strategies and security controls.

## Features

- Correlates MITRE ATT&CK techniques with Microsoft 365 audit operations
- Groups related attack techniques for comprehensive analysis
- Generates detailed detection strategies using audit logs
- Provides actionable security controls and mitigations
- Supports custom templates and formatting
- Includes batch processing capabilities
- Docker support for containerized deployment
- Comprehensive test coverage (>80%)

## Quick Start

### Standard Installation

```bash
# Install package
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"
```

### Docker Installation

```bash
# Build Docker image
make docker-build

# Run container
make docker-run
```

### Basic Usage

#### Recommended Starting Command
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

The tool comes with pre-configured default CSV files:
- office_suite_description_mitre_dump.csv (MITRE techniques)
- idp_description_mitre_dump.csv (IDP techniques)
- audit_operations.csv (Audit operations)

#### Python API Usage
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

## Documentation

Comprehensive documentation is available in the [docs](docs/) directory:

- [Getting Started Guide](docs/getting_started.md) - Installation and basic usage
- [Configuration Guide](docs/configuration.md) - Customization options
- [Templates Guide](docs/templates.md) - Output customization
- [Advanced Usage](docs/advanced_usage.md) - Complex features and examples

## Development

### Prerequisites

- Python 3.13 or higher
- Docker (optional)
- Make (optional)

### Development Setup

```bash
# Setup development environment
make dev-setup

# Run tests
make test

# Run linting
make lint

# Format code
make format
```

### Testing

```bash
# Run all tests with coverage
make test

# Generate coverage report
make coverage

# Run security checks
make security-check
```

### Docker Development

```bash
# Build development image
make docker-build

# Run with mounted volumes
make docker-run
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

The tool uses two main data sources:

1. MITRE ATT&CK techniques CSV file containing:
   - Technique ID
   - Tactic
   - Technique Name
   - Description

2. Microsoft 365 audit operations CSV file containing:
   - Operation Name
   - Friendly Name
   - Description

## Output

The generated threat model includes:

- Attack vector analysis
- Detection strategies using audit logs
- Example detection rules
- Security controls and mitigations
- Compliance requirements

## Make Commands

Common development commands:

- `make all`: Clean, install, test, and lint
- `make clean`: Remove build artifacts and caches
- `make test`: Run tests with coverage
- `make lint`: Run linting checks
- `make format`: Format code with black
- `make docker-build`: Build Docker image
- `make docker-run`: Run Docker container
- `make help`: Show all available commands

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

See our [Contributing Guide](CONTRIBUTING.md) for more details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Status

- Version: 0.2.0
- Development Stage: Alpha
- Test Coverage: >80%
- Build Status: Passing
