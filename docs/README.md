# Microsoft 365 Threat Model Generator Documentation

## Overview
The Microsoft 365 Threat Model Generator is a Python package that creates comprehensive threat models for Microsoft 365 and Entra ID environments. It analyzes MITRE ATT&CK techniques and Microsoft 365 audit operations to generate detailed threat models with detection strategies and security controls.

## Documentation Structure

### 1. [Getting Started](getting_started.md)
- Prerequisites
- Installation
- Basic Usage
- Input Data Requirements
- Output Format
- Batch Processing
- Next Steps

### 2. [Configuration Guide](configuration.md)
- Environment Variables
- Project Configuration
- Data Processing Settings
- Correlation Settings
- Logging Configuration
- Output Settings
- Cache Settings
- API Settings
- Best Practices

### 3. [Templates Guide](templates.md)
- Template Structure
- Template Variables
- Customization Examples
- Template Functions
- Best Practices
- Testing Templates
- Template Migration
- Advanced Features

### 4. [Advanced Usage](advanced_usage.md)
- Batch Processing
- Custom Correlation Rules
- Template Customization
- Advanced Data Processing
- Performance Optimization
- Error Handling and Logging
- Testing and Validation

## Quick Start

### Installation
```bash
# Basic installation
pip install -e .

# With development dependencies
pip install -e ".[dev]"
```

### Basic Usage
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

### Command Line Interface
```bash
# Generate threat model with default settings
python -m threat_model

# Specify custom paths
python -m threat_model \
  --mitre-path path/to/mitre.csv \
  --audit-path path/to/audit.csv \
  --output threat_model_output.md
```

## Key Features
1. MITRE ATT&CK Integration
   - Correlates techniques with audit operations
   - Groups related attack patterns
   - Provides comprehensive coverage

2. Detection Strategies
   - Audit log analysis
   - Behavioral analytics
   - Correlation rules
   - Example detection patterns

3. Security Controls
   - Technical controls
   - Administrative measures
   - Monitoring requirements
   - Implementation guidance

4. Batch Processing
   - Parallel processing
   - Efficient generation
   - Customizable sections
   - Progress tracking

## Contributing
See our [Contributing Guide](CONTRIBUTING.md) for details on:
- Code style
- Testing requirements
- Pull request process
- Development setup

## Support
- GitHub Issues: Report bugs and request features
- Documentation: Comprehensive guides and examples
- Community: Discussion and collaboration

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.