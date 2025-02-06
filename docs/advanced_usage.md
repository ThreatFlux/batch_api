# Advanced Usage Guide

## Batch Processing

### Overview
The batch processing feature allows you to generate multiple threat models efficiently by processing techniques in parallel batches.

### Configuration
```python
from threat_model.core import ThreatModelGenerator

generator = ThreatModelGenerator(api_key="your-api-key")

# Configure batch size in config.py
BATCH_SIZE = 5  # Adjust based on your needs
```

### Command Line Usage
```bash
python -m threat_model --batch \
  --sections "Authentication" "Data Access" "Application Security" \
  --output batch_results.md
```

### Python API Usage
```python
# Load data
generator.load_data(
    mitre_path="data/mitre.csv",
    idp_path="data/idp.csv",
    audit_path="data/audit.csv"
)

# Generate batch threat models
generator.generate_threat_model_batch(
    sections=["Authentication", "Data Access"],
    output_file="batch_results.md"
)
```

## Custom Correlation Rules

### Modifying Correlation Weights
```python
# In config.py
CORRELATION_WEIGHTS = {
    "exact_match": 1.0,      # Exact string matches
    "partial_match": 0.5,    # Partial string matches
    "description_similarity": 0.3  # TF-IDF similarity score
}
```

### Custom Correlation Logic
```python
from threat_model.core import DataProcessor

class CustomDataProcessor(DataProcessor):
    def _calculate_correlation_score(
        self,
        technique: pd.Series,
        operation: pd.Series,
        similarity_score: float
    ) -> float:
        # Your custom correlation logic here
        score = super()._calculate_correlation_score(
            technique, operation, similarity_score
        )
        
        # Add custom scoring rules
        if your_condition:
            score += your_adjustment
            
        return min(score, 1.0)
```

## Template Customization

### Custom Template Loading
```python
class CustomGenerator(ThreatModelGenerator):
    def _load_templates(self) -> Dict[str, str]:
        templates = super()._load_templates()
        
        # Add custom templates
        templates['custom_template'] = """
        # Custom Format
        {your_variables}
        """
        
        return templates
```

### Dynamic Template Selection
```python
def _create_section(self, technique_group: List[str]) -> str:
    # Select template based on technique characteristics
    if self._is_high_risk(technique_group):
        template = self.templates['high_risk_template']
    else:
        template = self.templates['standard_template']
        
    return template.render(**section_data)
```

## Advanced Data Processing

### Custom Technique Grouping
```python
class CustomDataProcessor(DataProcessor):
    def get_technique_groups(self) -> List[List[str]]:
        groups = []
        processed = set()
        
        for technique_id in self.correlation_matrix:
            if technique_id in processed:
                continue
                
            # Custom grouping logic
            group = self._create_custom_group(technique_id)
            groups.append(list(group))
            processed.update(group)
            
        return groups
        
    def _create_custom_group(self, technique_id: str) -> Set[str]:
        # Implement custom grouping logic
        pass
```

### Enhanced Similarity Calculation
```python
class CustomDataProcessor(DataProcessor):
    def correlate_techniques_with_operations(self) -> Dict[str, List[Tuple[str, float]]]:
        # Custom vectorization
        self.vectorizer = TfidfVectorizer(
            stop_words='english',
            ngram_range=(1, 2),
            max_features=1000
        )
        
        # Proceed with correlation
        return super().correlate_techniques_with_operations()
```

## Performance Optimization

### Memory Management
```python
class OptimizedGenerator(ThreatModelGenerator):
    def generate_threat_model_batch(self, sections: List[str], output_file: str) -> None:
        # Process in smaller chunks
        chunk_size = 1000
        
        for i in range(0, len(sections), chunk_size):
            chunk = sections[i:i + chunk_size]
            self._process_chunk(chunk, output_file)
            
    def _process_chunk(self, chunk: List[str], output_file: str) -> None:
        # Process chunk and append to output
        pass
```

### Caching Implementation
```python
from functools import lru_cache
import hashlib
import json

class CachedGenerator(ThreatModelGenerator):
    @lru_cache(maxsize=1000)
    def _create_section(self, technique_group: str) -> str:
        # Cache based on technique group hash
        return super()._create_section(technique_group)
        
    def _get_cache_key(self, data: Any) -> str:
        # Create deterministic cache key
        return hashlib.md5(
            json.dumps(data, sort_keys=True).encode()
        ).hexdigest()
```

## Error Handling and Logging

### Custom Error Handling
```python
class RobustGenerator(ThreatModelGenerator):
    def generate_threat_model_batch(self, sections: List[str], output_file: str) -> None:
        try:
            super().generate_threat_model_batch(sections, output_file)
        except Exception as e:
            self._handle_generation_error(e, sections, output_file)
            
    def _handle_generation_error(
        self,
        error: Exception,
        sections: List[str],
        output_file: str
    ) -> None:
        # Implement custom error recovery
        pass
```

### Enhanced Logging
```python
import logging
from typing import Any, Dict

class LoggedGenerator(ThreatModelGenerator):
    def __init__(self, api_key: str):
        super().__init__(api_key)
        self._setup_logging()
        
    def _setup_logging(self):
        # Configure detailed logging
        self.logger = logging.getLogger(__name__)
        handler = logging.FileHandler('threat_model.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
    def _log_operation(self, operation: str, data: Dict[str, Any]):
        # Log detailed operation information
        self.logger.info(
            f"Operation: {operation}\nData: {json.dumps(data, indent=2)}"
        )
```

## Testing and Validation

### Custom Validators
```python
class ValidationMixin:
    def validate_technique_model(self, model: str) -> bool:
        # Implement validation logic
        required_sections = [
            "Overview",
            "Attack Vectors",
            "Detection Strategy"
        ]
        
        return all(
            section in model
            for section in required_sections
        )
        
class ValidatedGenerator(ThreatModelGenerator, ValidationMixin):
    def generate_threat_model(self) -> str:
        model = super().generate_threat_model()
        
        if not self.validate_technique_model(model):
            raise ValueError("Generated model failed validation")
            
        return model
```

### Integration Testing
```python
class TestGenerator:
    def setup_method(self):
        self.generator = ThreatModelGenerator(api_key="test-key")
        self.test_data = self._load_test_data()
        
    def test_end_to_end(self):
        # Test complete generation process
        self.generator.load_data(
            mitre_path=self.test_data['mitre'],
            idp_path=self.test_data['idp'],
            audit_path=self.test_data['audit']
        )
        
        model = self.generator.generate_threat_model()
        assert self._validate_model(model)