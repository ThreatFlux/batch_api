# Advanced Usage Guide

This guide covers advanced features and usage patterns for the Microsoft 365 Threat Model Generator.

## Batch Processing

### Custom Batch Processing

```python
from threat_model.core import BatchProcessor

# Initialize processor
processor = BatchProcessor(client, data_processor)

# Process specific techniques
technique_ids = ["T1110", "T1136", "T1078"]
processor.process_batch(technique_ids, batch_start=0)
```

### Batch Size Configuration

The batch processor can be tuned through environment variables:
```bash
export BATCH_SIZE=10
export MAX_TOKENS=4096
```

## Docker Advanced Usage

### Multi-Stage Builds

The project uses three Docker stages for different purposes:

1. **Builder Stage**
```bash
# Build only the builder stage
docker build --target builder -t batch-api:builder .
```

2. **Development Stage**
```bash
# Build development image with source mounting
docker build --target development -t batch-api:dev .

# Run with development configuration
docker run -it --rm \
    -v $(pwd)/src:/workspace/src \
    -v $(pwd)/tests:/workspace/tests \
    -v $(pwd)/data:/workspace/data \
    -v $(pwd)/output:/workspace/output \
    -e PYTHONPATH=/workspace/src \
    batch-api:dev
```

3. **Production Stage**
```bash
# Build production image
docker build --target production -t batch-api:prod .

# Run with minimal configuration
docker run -it --rm \
    -v $(pwd)/data:/workspace/data \
    -v $(pwd)/output:/workspace/output \
    batch-api:prod
```

### Health Check Customization

```bash
# Custom health check configuration
docker run -it --rm \
    --health-cmd="python3 -c 'import threat_model; print(\"Custom health check\")'" \
    --health-interval=1m \
    --health-timeout=10s \
    --health-retries=5 \
    batch-api:prod
```

## Advanced API Usage

### Custom Data Processing

```python
from threat_model.core import DataProcessor

# Initialize processor
processor = DataProcessor()

# Load custom data
processor.load_csv("custom_mitre.csv", "mitre")
processor.load_csv("custom_idp.csv", "idp")
processor.load_csv("custom_audit.csv", "audit")

# Custom correlation
processor.correlate_techniques_with_operations(
    threshold=0.7,
    use_custom_nlp=True
)
```

### Template Customization

```python
from threat_model.core import ThreatModelGenerator

# Initialize with custom templates
generator = ThreatModelGenerator(api_key="your-key")

# Load custom template
generator.templates = {
    "section_template": """
    # Custom Threat Model: {{ technique_name }}
    Risk Level: {{ risk_level }}
    Impact: {{ impact }}
    ...
    """,
    "detection_template": """
    ## Detection Strategy
    ```sql
    {{ detection_strategy.sql_rule }}
    ```
    """
}

# Generate with custom format
threat_model = generator.generate_threat_model()
```

## Advanced Testing

### Integration Testing

```bash
# Run integration tests
pytest tests/integration/ -v

# Run with specific markers
pytest -m "integration and not slow"
```

### Performance Testing

```bash
# Run performance tests
pytest tests/performance/ --durations=0

# Profile specific tests
python -m cProfile -o profile.stats tests/performance/test_batch.py
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Advanced CI Pipeline

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.13]
        docker-stage: [builder, development, production]
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Build Docker Stage
      run: |
        docker build --target ${{ matrix.docker-stage }} \
          -t batch-api:${{ matrix.docker-stage }} .
    
    - name: Run Tests
      run: |
        make ci-test
```

## Security Considerations

### API Key Management

```python
# Use environment variables
import os
api_key = os.getenv("ANTHROPIC_API_KEY")

# Or use a secrets manager
from azure.keyvault.secrets import SecretClient
client = SecretClient(vault_url="vault_url", credential=credential)
api_key = client.get_secret("anthropic-api-key").value
```

### Docker Security

1. **Non-root User**
```dockerfile
USER python_builder
```

2. **Minimal Permissions**
```dockerfile
RUN chown -R python_builder:python_builder /workspace
```

3. **Health Checks**
```dockerfile
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python3 -c "import threat_model; print('Health check passed')" || exit 1
```

## Performance Optimization

### Batch Processing Optimization

1. **Adjust Batch Size**
```python
processor = BatchProcessor(
    client,
    data_processor,
    batch_size=20,
    max_tokens=8192
)
```

2. **Parallel Processing**
```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=4) as executor:
    futures = [
        executor.submit(processor.process_batch, batch, i)
        for i, batch in enumerate(batches)
    ]
```

### Memory Management

```python
# Clear cache between batches
import gc

def process_large_dataset():
    for batch in batches:
        process_batch(batch)
        gc.collect()  # Force garbage collection
```

## Troubleshooting

### Common Issues

1. **Rate Limiting**
```python
from anthropic import RateLimitError

try:
    result = processor.process_batch(batch)
except RateLimitError:
    time.sleep(60)  # Wait before retry
```

2. **Memory Issues**
```bash
# Increase Docker memory limit
docker run -it --rm \
    --memory=4g \
    --memory-swap=4g \
    batch-api:prod
```

### Logging

```python
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)
logger.debug("Processing batch %d", batch_number)
```

## Contributing

### Development Workflow

1. **Setup Development Environment**
```bash
make dev-setup
```

2. **Run Tests**
```bash
make test
make coverage
```

3. **Code Quality**
```bash
make lint
make format
make security-check
```

4. **Submit Changes**
```bash
git checkout -b feature/your-feature
# Make changes
make ci-test  # Ensure all checks pass
git push origin feature/your-feature
