# Microsoft 365 Threat Model Generator

A Python package for generating comprehensive threat models for Microsoft 365 and Entra ID environments. The tool analyzes MITRE ATT&CK techniques and Microsoft 365 audit operations to create detailed threat models with detection strategies and security controls.

## Features

- Correlates MITRE ATT&CK techniques with Microsoft 365 audit operations
- Groups related attack techniques for comprehensive analysis
- Generates detailed detection strategies using audit logs
- Provides actionable security controls and mitigations
- Supports custom templates and formatting

## Installation

```bash
pip install -e .
```

## Usage

```python
from threat_model.core import ThreatModelGenerator

# Initialize generator
generator = ThreatModelGenerator(api_key="your-anthropic-api-key")

# Load data
generator.load_data(
    mitre_path="data/mitre_techniques.csv",
    audit_path="data/audit_operations.csv"
)

# Generate threat model
threat_model = generator.generate_threat_model()
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

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
pylint src/threat_model
```

## License

MIT License