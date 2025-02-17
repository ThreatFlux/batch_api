#!/usr/bin/env python3
"""Script to process summary and submit to Claude API batch job."""

import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, NoReturn

# Configure logging first
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Third-party imports
import anthropic
from ruamel.yaml import YAML
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages.batch_create_params import Request

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

# Local imports
try:
    from src.threat_model.core.summary_processor import SummaryConfig, SummaryProcessor
except ImportError as e:
    logger.error(f"Failed to import summary_processor: {e}")
    sys.exit(1)

def create_client() -> anthropic.Anthropic:
    """Create and return an Anthropic client instance."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable is not set")
    return anthropic.Anthropic(api_key=api_key)

def create_batch_request(summary_data: Dict[str, Any], custom_id: str) -> Request:
    """Create a batch request for the summary data."""
    # Extract task and environment from summary
    task = summary_data.get("messages", [{}])[1].get("metadata", {}).get("task", "")
    environment = summary_data.get("messages", [{}])[1].get("metadata", {}).get("environment", {})

    # Create system message
    system_message = (
        """# Technical Summary Analysis Protocol
## Overview
You are an expert technical analyst responsible for creating comprehensive, detailed summaries from large datasets. Your task is to condense approximately 128,000 tokens of technical information into a precise, well-structured 8,000-token summary that maintains technical accuracy while highlighting critical information.

## Data Analysis Framework

### 1. Initial Data Processing
When analyzing input data, systematically evaluate:

```plaintext
Primary Analysis Components:
├── Technical Architecture
│   ├── System Components
│   ├── Dependencies
│   └── Integration Points
├── Implementation Details
│   ├── Code Snippets
│   ├── Configuration Files
│   └── Deployment Scripts
├── Testing & Validation
│   ├── Test Results
│   ├── Coverage Reports
│   └── Performance Metrics
├── Issues & Resolutions
│   ├── Error Logs
│   ├── Debug Information
│   └── Applied Solutions
└── Documentation
    ├── API References
    ├── Setup Guides
    └── Maintenance Procedures
```

### 2. Content Organization Structure

#### A. Executive Overview (10% of summary)
- Project scope and objectives
- Key achievements and challenges
- Critical metrics and outcomes
- High-level technical architecture

#### B. Technical Implementation (30% of summary)
```plaintext
Required Components:
1. System Architecture
   - Component diagram
   - Service interactions
   - Data flow patterns

2. Implementation Details
   - Full code snippets
   - Configuration examples
   - Deployment specifications

3. Integration Points
   - API endpoints
   - Service dependencies
   - External system connections
```

#### C. Operational Analysis (20% of summary)
- Performance metrics and benchmarks
- Resource utilization statistics
- Scaling considerations
- Security implementations

#### D. Issue Analysis (20% of summary)
```plaintext
For each significant issue:
1. Problem Definition
   - Error codes
   - Stack traces
   - System state

2. Impact Analysis
   - Affected components
   - User impact
   - System degradation

3. Resolution Details
   - Applied fixes
   - Configuration changes
   - Validation steps
```

#### E. Recommendations & Action Items (20% of summary)
- Immediate actions required
- Short-term improvements
- Long-term strategic changes
- Risk mitigation strategies

### 3. Technical Detail Requirements

#### Code Snippet Documentation
All code snippets must include:
```plaintext
1. Language/framework version
2. Dependencies and prerequisites
3. Complete implementation (no truncation)
4. Example usage
5. Expected output
6. Error handling
```

#### Configuration Examples
Must provide:
```yaml
# Example configuration structure
configuration:
  version: "specific-version"
  environment: "context"
  components:
    - name: "component-name"
      version: "x.y.z"
      configuration:
        key1: "detailed-value1"
        key2: "detailed-value2"
  dependencies:
    - name: "dependency-name"
      version: "x.y.z"
      configuration: {}
```

#### Error Documentation
For each error, document:
```plaintext
Error Analysis Template:
1. Error Identifier
   - Error code/message
   - Timestamp
   - Environment context

2. Technical Details
   - Stack trace
   - System state
   - Related logs

3. Resolution Path
   - Investigation steps
   - Applied solution
   - Verification method
```

### 4. Quality Control Checklist

#### Technical Accuracy
- [ ] All versions and dependencies specified
- [ ] Code snippets complete and functional
- [ ] Configuration examples validated
- [ ] Error codes and solutions verified

#### Comprehensiveness
- [ ] All critical components covered
- [ ] Implementation details complete
- [ ] Error scenarios documented
- [ ] Solutions provided for known issues

#### Clarity and Structure
- [ ] Logical information flow
- [ ] Consistent formatting
- [ ] Clear section delineation
- [ ] Appropriate technical depth

### 5. Output Format Requirements

#### Document Structure
```markdown
# Technical Summary Report

## Executive Overview
[Concise project overview with critical metrics]

## Technical Architecture
[Detailed system architecture with diagrams]

## Implementation Details
[Complete code snippets and configurations]

## Operational Analysis
[Performance metrics and operational data]

## Issue Analysis and Resolution
[Detailed error analysis and solutions]

## Recommendations
[Prioritized action items and improvements]

## Appendix
[Supporting technical documentation]
```

#### Code Block Formatting
```plaintext
For all code snippets:
1. Use appropriate language tags
2. Include complete implementations
3. Add inline comments for clarity
4. Provide usage examples
5. Show expected outputs
6. Document error handling
```

### 6. Critical Focus Areas

#### Technical Depth
- Provide complete technical implementations
- Include all relevant configuration details
- Document system interactions comprehensively
- Explain technical decisions and trade-offs

#### Error Analysis
- Document full error contexts
- Include complete stack traces
- Provide detailed resolution steps
- Verify solution effectiveness

#### Performance Metrics
- Include specific benchmark data
- Document resource utilization
- Provide scaling metrics
- Detail optimization opportunities

#### Security Considerations
- Document authentication methods
- Detail authorization processes
- Specify encryption requirements
- List security best practices

### 7. Final Validation Steps

1. Technical Verification
- Validate all code snippets
- Verify configuration examples
- Test documented solutions
- Check version compatibility

2. Content Completeness
- Ensure all sections covered
- Verify technical accuracy
- Confirm solution validity
- Check recommendation feasibility

3. Format Compliance
- Maintain 8000-token limit
- Follow structure guidelines
- Use consistent formatting
- Include all required sections

4. Quality Assurance
- Technical accuracy check
- Clarity verification
- Completeness validation
- Format compliance review

Remember: The goal is to create a technically precise, comprehensive summary that maintains all critical information while being concise and well-structured. Each section should provide valuable insights and actionable information for the reader.""")

    # Create user message
    user_message = f"""
Task: {task}

Large Context DATA:
{environment}

Please provide a detailed technical report based no your instructions. output as much data as possible
"""

    return Request(
        custom_id=custom_id,
        params=MessageCreateParamsNonStreaming(
            model="claude-3-5-sonnet-20241022",
            max_tokens=8192,
            system=system_message,
            messages=[{
                "role": "user",
                "content": user_message
            }]
        )
    )

def submit_batch_request(client: anthropic.Anthropic, summary_data: Dict[str, Any]) -> str:
    """Submit batch request and return batch ID."""
    request = create_batch_request(summary_data, f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    message_batch = client.messages.batches.create(requests=[request])
    logger.info(f"Batch submitted successfully. Batch ID: {message_batch.id}")
    return message_batch.id

def wait_for_batch_completion(client: anthropic.Anthropic, batch_id: str, interval: int = 60) -> None:
    """Wait for batch request to complete."""
    while True:
        message_batch = client.messages.batches.retrieve(batch_id)
        if message_batch.processing_status == "ended":
            logger.info(f"Batch {batch_id} processing completed")
            break
        logger.info(f"Batch {batch_id} still processing. Waiting {interval} seconds.")
        time.sleep(interval)

def get_batch_results(client: anthropic.Anthropic, batch_id: str) -> str:
    """Get batch results as a string."""
    content = []
    for result in client.messages.batches.results(batch_id):
        if result.result.type == "succeeded":
            message_content = result.result.message.content
            for content_item in message_content:
                if content_item.type == "text":
                    content.append(content_item.text)
    return "\n\n".join(content)

def save_yaml_output(summary: Dict[str, Any], batch_response: str, output_dir: str) -> None:
    """Save complete YAML output including batch response."""
    os.makedirs(output_dir, exist_ok=True)
    
    # Add batch response to summary
    summary["batch_response"] = batch_response
    
    # Generate unique filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"summary_{timestamp}.yaml")
    
    try:
        # Create YAML object
        yaml_writer = YAML()
        yaml_writer.indent(mapping=2, sequence=4, offset=2)
        
        # Write to file
        with open(output_file, 'w') as f:
            yaml_writer.dump(summary, f)
        logger.info(f"Complete summary saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving YAML output: {str(e)}")
        raise

def main() -> None:
    """Process summary and submit batch job."""
    # Configure the processor
    config = SummaryConfig(
        max_length=8192,
        batch_size=1,
        output_format="yaml",
        schema_validation=True
    )
    
    processor = SummaryProcessor(config)
    
    # Read the input file
    input_file = "summary_docs/cline_task_jan-28-2025_10-02-35-pm.md"
    with open(input_file, 'r') as f:
        content = f.read()
    
    # Generate summary
    summary = processor.generate_summary(content)
    
    # Create Anthropic client
    client = create_client()
    
    # Submit batch request
    batch_id = submit_batch_request(client, summary)
    
    # Wait for completion
    wait_for_batch_completion(client, batch_id)
    
    # Get batch results
    batch_response = get_batch_results(client, batch_id)
    
    # Save complete YAML output
    save_yaml_output(summary, batch_response, "summary_docs")

if __name__ == "__main__":
    main()
