# Configuration Guide

## Overview
The Microsoft 365 Threat Model Generator provides various configuration options to customize its behavior. This guide covers all available settings and their usage.

## Configuration Files

### 1. Environment Variables (.env)
```plaintext
# Required
ANTHROPIC_API_KEY=your-api-key-here

# Optional
LOG_LEVEL=INFO  # Default logging level
```

### 2. Project Configuration (config.py)

#### Model Settings
```python
# Model configuration
DEFAULT_MODEL = "claude-3-5-sonnet-20241022"
MAX_TOKENS = 8192
BATCH_SIZE = 5
```

#### Path Configuration
```python
# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
PROMPTS_DIR = PROJECT_ROOT / "src/threat_model/prompts"
OUTPUT_DIR = PROJECT_ROOT / "output"
```

#### Data Processing Settings
```python
CSV_SETTINGS = {
    "mitre": {
        "required_columns": ["TID", "Tactic", "Technique", "Description"],
        "index_column": "TID",
        "encoding": "utf-8"
    },
    "idp": {
        "required_columns": ["TID", "Tactic", "Technique", "Description"],
        "index_column": "TID",
        "encoding": "utf-8"
    },
    "audit": {
        "required_columns": ["FriendlyName", "Operation", "Description"],
        "index_column": "Operation",
        "encoding": "utf-8"
    }
}
```

#### Correlation Settings
```python
CORRELATION_WEIGHTS = {
    "exact_match": 1.0,
    "partial_match": 0.5,
    "description_similarity": 0.3
}
```

## Customization Options

### 1. Logging Configuration
```python
# Logging settings
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"
```

### 2. Output Settings
```python
# Output configuration
THREAT_MODEL_TEMPLATE = "threat_model_template.md"
OUTPUT_FILE = "threat_model.md"
```

### 3. Cache Settings
```python
# Cache configuration
CACHE_DIR = PROJECT_ROOT / ".cache"
CACHE_EXPIRY = 3600  # 1 hour in seconds
```

### 4. API Settings
```python
# API configuration
API_RETRY_ATTEMPTS = 3
API_RETRY_DELAY = 1  # seconds
```

## Template Customization

### 1. Template Location
Templates are stored in `src/threat_model/prompts/templates.yaml`

### 2. Available Templates
- technique_model_template: Individual technique analysis
- section_template: Section formatting
- correlation_prompt: Correlation analysis
- group_prompt: Technique grouping
- validation_prompt: Content validation

### 3. Template Variables
Each template supports specific variables:

#### Technique Model Template:
- technique_name
- technique_id
- overview
- attack_vectors
- detection_fields
- example_logs
- etc.

#### Section Template:
- section_title
- risk_level
- impact
- likelihood
- techniques
- operations
- detection_strategy
- controls

## Command Line Arguments

### Basic Arguments
```bash
--mitre-path    Path to MITRE CSV file
--idp-path      Path to IDP CSV file
--audit-path    Path to audit operations CSV file
--output        Output file path
```

### Batch Processing Arguments
```bash
--batch         Enable batch processing
--sections      Section names for batch processing
```

## Performance Tuning

### 1. Batch Processing
Adjust `BATCH_SIZE` based on your needs:
```python
BATCH_SIZE = 5  # Default
```

### 2. Memory Management
Configure cache settings:
```python
CACHE_EXPIRY = 3600  # Cache duration
```

### 3. API Optimization
Tune API retry settings:
```python
API_RETRY_ATTEMPTS = 3
API_RETRY_DELAY = 1
```

## Error Handling

### 1. Logging Levels
Available logging levels:
- DEBUG: Detailed debugging information
- INFO: General information
- WARNING: Warning messages
- ERROR: Error messages
- CRITICAL: Critical errors

### 2. Error Retry
Configure retry behavior for API calls:
```python
API_RETRY_ATTEMPTS = 3  # Number of retries
API_RETRY_DELAY = 1    # Delay between retries
```

## Best Practices

1. Environment Variables
   - Keep API keys in .env file
   - Don't commit sensitive information
   - Use appropriate logging levels

2. Performance
   - Adjust batch size based on resources
   - Monitor memory usage
   - Configure appropriate cache settings

3. Templates
   - Back up templates before modification
   - Test changes thoroughly
   - Maintain consistent formatting

4. Error Handling
   - Monitor logs regularly
   - Set appropriate logging levels
   - Configure meaningful retry settings