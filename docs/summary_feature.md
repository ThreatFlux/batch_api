# Summary Feature Technical Specification

## 1. Feature Overview

### Purpose
The Summary Feature extends the Microsoft 365 Threat Model Generator to provide verbose summary generation capabilities, processing batch inputs and creating structured YAML output that captures the full context of threat model generation conversations.

### Goals
- Process large context inputs from batch jobs
- Generate comprehensive summaries
- Output standardized YAML format
- Ensure schema validation
- Maintain conversation history
- Support multimodal content

### Key Functionality
1. Batch Processing
   - Handle multiple input contexts
   - Process large text inputs
   - Support parallel processing
   - Manage rate limiting

2. Summary Generation
   - Context analysis
   - Key point extraction
   - Structured summarization
   - Metadata generation

3. YAML Output
   - Schema-compliant generation
   - Validation enforcement
   - Pretty printing
   - Error handling

### Integration Points
1. CLI Integration
   ```bash
   python -m threat_model --summary-output summary.yaml --batch
   ```

2. API Integration
   ```python
   from threat_model.core import ThreatModelGenerator
   
   generator = ThreatModelGenerator()
   generator.generate_summary(context, output_path="summary.yaml")
   ```

3. Batch Processor Integration
   - Extends existing batch processing
   - Adds summary generation
   - Supports YAML output

## 2. Technical Architecture

### Component Design
```
src/threat_model/core/
└── summary_processor.py
    ├── SummaryProcessor
    │   ├── process_batch()
    │   ├── generate_summary()
    │   └── create_yaml()
    ├── ContextAnalyzer
    │   ├── analyze_content()
    │   └── extract_key_points()
    ├── YAMLGenerator
    │   ├── generate_yaml()
    │   └── validate_schema()
    └── SchemaValidator
        ├── validate()
        └── error_handling()
```

### Class Structure

1. SummaryProcessor
   ```python
   class SummaryProcessor:
       def __init__(self, config: Config):
           self.config = config
           self.analyzer = ContextAnalyzer()
           self.generator = YAMLGenerator()
           self.validator = SchemaValidator()

       def process_batch(self, inputs: List[str]) -> None
       def generate_summary(self, context: str) -> Dict
       def create_yaml(self, data: Dict, path: str) -> None
   ```

2. ContextAnalyzer
   ```python
   class ContextAnalyzer:
       def analyze_content(self, content: str) -> Dict
       def extract_key_points(self, content: str) -> List[str]
   ```

3. YAMLGenerator
   ```python
   class YAMLGenerator:
       def generate_yaml(self, data: Dict) -> str
       def validate_schema(self, data: Dict) -> bool
   ```

4. SchemaValidator
   ```python
   class SchemaValidator:
       def validate(self, data: Dict) -> bool
       def error_handling(self, errors: List[str]) -> None
   ```

### Data Flow
1. Input Processing
   ```
   Raw Input → BatchProcessor → SummaryProcessor → ContextAnalyzer
   ```

2. Summary Generation
   ```
   ContextAnalyzer → Key Points → Metadata → Summary
   ```

3. YAML Creation
   ```
   Summary → YAMLGenerator → SchemaValidator → Output File
   ```

## 3. Implementation Details

### Module Specifications

1. summary_processor.py
   ```python
   from dataclasses import dataclass
   from typing import List, Dict, Optional
   
   @dataclass
   class SummaryConfig:
       max_length: int = 1000
       batch_size: int = 10
       output_format: str = "yaml"
   
   class SummaryProcessor:
       # Implementation details...
   ```

2. Configuration Options
   ```python
   # config.py additions
   summary_config = {
       "max_length": 1000,
       "batch_size": 10,
       "output_format": "yaml",
       "schema_validation": True
   }
   ```

3. CLI Arguments
   ```python
   # __main__.py additions
   parser.add_argument(
       "--summary-output",
       help="Path for summary YAML output",
       type=str,
       default="summary.yaml"
   )
   ```

### Schema Implementation
```yaml
# schema/summary.yaml
$schema: http://json-schema.org/draft-07/schema#
title: Summary Output Schema
type: array
items:
  type: object
  required:
    - conversation_id
    - messages
  properties:
    # ... (full schema as provided)
```

## 4. Testing Strategy

### Unit Tests
1. SummaryProcessor Tests
   ```python
   # test_summary_processor.py
   def test_process_batch():
       # Test batch processing
   
   def test_generate_summary():
       # Test summary generation
   
   def test_create_yaml():
       # Test YAML creation
   ```

2. Schema Validation Tests
   ```python
   def test_schema_validation():
       # Test valid schema
   
   def test_schema_validation_errors():
       # Test invalid schema
   ```

3. Integration Tests
   ```python
   def test_end_to_end_summary():
       # Test complete workflow
   ```

### Performance Testing
1. Batch Processing
   - Test with various batch sizes
   - Measure processing time
   - Monitor memory usage

2. Large Input Handling
   - Test with large context inputs
   - Verify memory efficiency
   - Check processing limits

## 5. Documentation Updates

### User Documentation
1. Getting Started
   ```markdown
   # Using the Summary Feature
   
   Generate YAML summaries from batch processing:
   ```bash
   python -m threat_model --summary-output summary.yaml --batch
   ```
   ```

2. Configuration Guide
   ```markdown
   # Summary Feature Configuration
   
   Configure summary generation in config.py:
   ```python
   summary_config = {
       "max_length": 1000  # Maximum summary length
   }
   ```
   ```

3. API Documentation
   ```markdown
   # Summary API Reference
   
   ```python
   # Generate summaries programmatically
   generator = ThreatModelGenerator()
   generator.generate_summary(context)
   ```
   ```

## 6. Implementation Timeline

1. Phase 1: Core Implementation
   - Create summary_processor.py
   - Implement basic functionality
   - Add schema validation

2. Phase 2: Integration
   - Add CLI support
   - Integrate with batch processor
   - Implement YAML output

3. Phase 3: Testing
   - Create test suite
   - Add performance tests
   - Implement schema tests

4. Phase 4: Documentation
   - Update user docs
   - Add API documentation
   - Create usage examples

## 7. Future Considerations

1. Performance Optimizations
   - Parallel processing
   - Caching mechanisms
   - Memory optimization

2. Feature Extensions
   - Additional output formats
   - Custom templates
   - Advanced summarization

3. Integration Enhancements
   - API endpoints
   - Webhook support
   - Event streaming
