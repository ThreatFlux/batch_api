# Getting Started with Microsoft 365 Threat Model Generator

## Prerequisites

1. Python Environment
   - Python 3.8 or higher
   - pip package manager
   - virtualenv (recommended)

2. API Access
   - Anthropic API key for Claude 3 Sonnet
   - Environment file (.env) configuration

3. Optional Requirements
   - Docker for containerized deployment
   - Make for development automation

## Installation

### Standard Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd threat-model-generator
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the package:
   ```bash
   # Basic installation
   pip install -e .

   # With development dependencies
   pip install -e ".[dev]"
   ```

4. Configure environment:
   ```bash
   # Create .env file
   echo "ANTHROPIC_API_KEY=your-api-key-here" > .env
   ```

### Docker Installation

1. Build the Docker image:
   ```bash
   make docker-build
   ```

2. Run the container:
   ```bash
   make docker-run
   ```

## Development Setup

### Using Make Commands

1. Setup development environment:
   ```bash
   make dev-setup
   ```

2. Run tests:
   ```bash
   make test
   ```

3. Run linting:
   ```bash
   make lint
   ```

4. Format code:
   ```bash
   make format
   ```

5. Run security checks:
   ```bash
   make security-check
   ```

6. Generate coverage report:
   ```bash
   make coverage
   ```

### Common Make Targets

- `make all`: Clean, install, test, and lint
- `make clean`: Remove build artifacts and caches
- `make dev`: Format, lint, and test
- `make prod`: Clean, test, and build Docker image
- `make help`: Show all available targets

## Basic Usage

### Command Line Interface

1. Basic threat model generation (recommended starting point):
   ```bash
   python -m threat_model \
     --mitre-path office_suite_description_mitre_dump.csv \
     --idp-path idp_description_mitre_dump.csv \
     --audit-path audit_operations.csv \
     --output threat_model.md \
     --batch

   # Or simply use Make (uses same defaults)
   make run
   ```

   Note: The tool comes with default CSV files pre-configured:
   - office_suite_description_mitre_dump.csv (MITRE techniques)
   - idp_description_mitre_dump.csv (IDP techniques)
   - audit_operations.csv (Audit operations)

2. Specify custom paths (if needed):
   ```bash
   python -m threat_model \
     --mitre-path path/to/mitre.csv \
     --audit-path path/to/audit.csv \
     --output threat_model_output.md
   ```

3. Batch processing:
   ```bash
   python -m threat_model --batch \
     --sections "Authentication" "Data Access"

   # Or using Make
   make run-batch
   ```

### Python API

```python
from threat_model.core import ThreatModelGenerator

# Initialize generator
generator = ThreatModelGenerator(api_key="your-anthropic-api-key")

# Load data
generator.load_data(
    mitre_path="data/mitre_techniques.csv",
    idp_path="data/idp_techniques.csv",
    audit_path="data/audit_operations.csv"
)

# Generate threat model
threat_model = generator.generate_threat_model()
```

### Docker Usage

1. Run with default settings:
   ```bash
   make docker-run
   ```

2. Run with custom arguments:
   ```bash
   docker run --rm -it \
     -v $(pwd)/data:/app/data \
     -v $(pwd)/output:/app/output \
     --env-file .env \
     threat-model-generator:latest \
     --batch --sections "Authentication" "Data Access"
   ```

## Input Data Requirements

1. MITRE Techniques CSV:
   - Required columns: TID, Tactic, Technique, Description
   - UTF-8 encoding
   - Example:
     ```csv
     TID,Tactic,Technique,Description
     T1110,Initial Access,Brute Force,"Adversaries may..."
     ```

2. IDP Techniques CSV:
   - Required columns: TID, Tactic, Technique, Description
   - UTF-8 encoding
   - Similar format to MITRE CSV

3. Audit Operations CSV:
   - Required columns: FriendlyName, Operation, Description
   - UTF-8 encoding
   - Example:
     ```csv
     FriendlyName,Operation,Description
     Add User,UserAdded,"User account created..."
     ```

## Testing

### Running Tests

1. Run all tests:
   ```bash
   make test
   ```

2. Run with coverage:
   ```bash
   make coverage
   ```

3. Run specific test file:
   ```bash
   pytest tests/test_generator.py -v
   ```

### Test Coverage

Current test coverage is maintained at 80% or higher across all modules:
- data_processor.py: ~90% coverage
- generator.py: ~85% coverage
- config.py: 100% coverage
- __main__.py: ~85% coverage

## Next Steps
- Review the [Configuration Guide](configuration.md) for customization options
- Check the [Templates Guide](templates.md) for output customization
- See [Advanced Usage](advanced_usage.md) for more features
