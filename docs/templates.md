# Templates Guide

## Overview
The Microsoft 365 Threat Model Generator uses a flexible template system based on YAML and Jinja2. This guide explains how to customize the output format using templates.

## Template Location
Templates are stored in `src/threat_model/prompts/templates.yaml`

## Template Structure

### 1. System Prompt
```yaml
system_prompt: |
  You are a cybersecurity expert specialized in threat modeling for Microsoft 365 and Entra ID.
  Your task is to analyze threats and create detailed threat models following a specific format.
  Focus on practical, actionable guidance backed by specific audit events and detection strategies.
```

### 2. Technique Model Template
```yaml
technique_model_template: |
  # Threat Model: {technique_name} ({technique_id}) in Microsoft 365 & Entra ID

  ## Overview
  {overview}

  ## Attack Vectors
  ### 1. {primary_vector}
  #### Description
  {description}

  #### Attack Scenarios
  {scenarios}

  #### Detection Fields
  ```json
  {
    "Important Fields": {
      "Operation": {operations},
      "SourceFileName": {file_patterns},
      "ClientIP": "string",
      "UserId": "string",
      "WorkloadName": {workloads},
      "ObjectId": "string",
      "TargetFilePath": "string",
      "AdditionalFields": {additional_fields}
    }
  }
  ```
```

### 3. Section Template
```yaml
section_template: |
  # {section_title}

  ## Threat Assessment
  Risk Level: {risk_level}
  Impact: {impact}
  Likelihood: {likelihood}

  ## MITRE Techniques
  {techniques}

  ## Audit Operations
  {operations}

  ## Detection Strategy
  ```json
  {detection_strategy}
  ```

  ## Mitigation Controls
  {controls}
```

## Template Variables

### 1. Technique Model Variables
- technique_name: Name of the MITRE technique
- technique_id: MITRE technique ID
- overview: Technique overview
- primary_vector: Primary attack vector
- description: Detailed description
- scenarios: Attack scenarios
- operations: Relevant audit operations
- file_patterns: File patterns to monitor
- workloads: Affected workloads
- additional_fields: Additional audit fields

### 2. Section Variables
- section_title: Section heading
- risk_level: Risk assessment level
- impact: Impact assessment
- likelihood: Likelihood assessment
- techniques: List of techniques
- operations: List of operations
- detection_strategy: Detection configuration
- controls: Security controls

## Customization Examples

### 1. Adding New Sections
```yaml
technique_model_template: |
  # Threat Model: {technique_name} ({technique_id})

  ## Overview
  {overview}

  ## Your New Section
  {new_section_content}

  [Rest of template...]
```

### 2. Modifying JSON Format
```yaml
detection_fields_template: |
  ```json
  {
    "CustomFormat": {
      "Category": "Authentication",
      "Fields": {
        "Primary": {operations},
        "Secondary": {additional_fields}
      }
    }
  }
  ```
```

### 3. Adding Custom Metadata
```yaml
section_template: |
  # {section_title}
  
  ## Metadata
  - Author: {author}
  - Date: {date}
  - Version: {version}

  [Rest of template...]
```

## Template Functions

### 1. Available Filters
- safe: Render content safely
- indent: Indent content
- trim: Remove whitespace
- join: Join list items
- tojson: Convert to JSON

### 2. Usage Examples
```yaml
# Indentation
description: |
  {{ description | indent(2) }}

# JSON Formatting
fields: |
  {{ fields | tojson(indent=2) }}

# List Joining
techniques: |
  {{ techniques | join(', ') }}
```

## Best Practices

### 1. Template Organization
- Keep templates modular
- Use consistent formatting
- Comment complex sections
- Maintain clear hierarchy

### 2. Variable Naming
- Use descriptive names
- Follow consistent conventions
- Document required variables
- Provide default values

### 3. JSON Formatting
- Use proper indentation
- Validate JSON structure
- Include example values
- Document field purposes

### 4. Markdown Formatting
- Use consistent headers
- Maintain clean structure
- Include proper spacing
- Follow markdown best practices

## Testing Templates

### 1. Validation Steps
1. Check variable replacement
2. Verify JSON formatting
3. Validate markdown structure
4. Test with sample data

### 2. Common Issues
- Missing variables
- Invalid JSON syntax
- Incorrect indentation
- Markdown rendering issues

## Template Migration

### 1. Backup Process
1. Copy existing templates
2. Document current format
3. Plan changes carefully
4. Test thoroughly

### 2. Version Control
- Track template changes
- Document modifications
- Maintain backwards compatibility
- Test all variations

## Advanced Features

### 1. Conditional Sections
```yaml
template: |
  {% if high_risk %}
  ## High Risk Alert
  {alert_content}
  {% endif %}
```

### 2. Loops and Iterations
```yaml
template: |
  {% for technique in techniques %}
  ### Technique: {{ technique.name }}
  {{ technique.description }}
  {% endfor %}
```

### 3. Custom Formatting
```yaml
template: |
  {% filter upper %}
  {important_notice}
  {% endfilter %}