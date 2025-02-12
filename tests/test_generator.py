"""Unit tests for the threat model generator module."""
from pathlib import Path
import json
from typing import Dict, Any, Generator
import pytest
from unittest.mock import Mock, patch, MagicMock
import yaml
from anthropic import Anthropic
from anthropic.types.messages.batch_create_params import Request
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming

from threat_model.core.batch_processor import BatchProcessor
from threat_model.core.generator import ThreatModelGenerator
from threat_model.core.config import DEFAULT_MODEL, MAX_TOKENS

@pytest.fixture
def mock_anthropic() -> Generator[Mock, None, None]:
    """Create a mock Anthropic client."""
    with patch('anthropic.Anthropic') as mock:
        yield mock

@pytest.fixture
def generator(mock_anthropic: Mock) -> ThreatModelGenerator:
    """Create a ThreatModelGenerator instance for testing."""
    return ThreatModelGenerator(api_key="test-key")

@pytest.fixture
def sample_data_dir(tmp_path: Path) -> Dict[str, Path]:
    """Create sample data files for testing."""
    # Create MITRE data
    mitre_data = """TID,Tactic,Technique,Description
T1110,Initial Access,Brute Force,Adversaries may attempt brute force
T1078,Defense Evasion,Valid Accounts,Adversaries may obtain credentials"""
    mitre_path = tmp_path / 'mitre.csv'
    mitre_path.write_text(mitre_data)

    # Create IDP data
    idp_data = """TID,Tactic,Technique,Description
T1110,Initial Access,Brute Force,IDP brute force description
T1078,Defense Evasion,Valid Accounts,IDP valid accounts description"""
    idp_path = tmp_path / 'idp.csv'
    idp_path.write_text(idp_data)

    # Create audit data
    audit_data = """FriendlyName,Operation,Description
Failed Login,UserLoginFailed,User login attempt failed
Account Access,UserLoggedIn,User successfully logged in"""
    audit_path = tmp_path / 'audit.csv'
    audit_path.write_text(audit_data)
    # Create templates
    templates = {
        'system_prompt': 'System prompt content',
        'technique_model_template': 'Technique model template',
        'section_template': 'Section template',
        'correlation_prompt': 'Correlation prompt',
        'group_prompt': 'Group prompt',
        'validation_prompt': 'Validation prompt'
    }
    template_dir = tmp_path / 'templates'
    template_dir.mkdir()
    template_path = template_dir / 'templates.yaml'
    with open(template_path, 'w') as f:
        yaml.dump(templates, f)
    return {
        'mitre_path': mitre_path,
        'idp_path': idp_path,
        'audit_path': audit_path,
        'template_path': template_path
    }

def test_init(generator: ThreatModelGenerator) -> None:
    """Test generator initialization."""
    assert generator.client is not None
    assert generator.data_processor is not None
    assert isinstance(generator.templates, dict)

def test_load_templates(generator: ThreatModelGenerator, tmp_path: Path) -> None:
    """Test template loading."""
    # Create test templates with expected structure
    templates = {
        'system_prompt': 'System prompt content',
        'technique_model_template': 'Technique model template',
        'section_template': 'Section template',
        'correlation_prompt': 'Correlation prompt',
        'group_prompt': 'Group prompt',
        'validation_prompt': 'Validation prompt'
    }
    template_path = tmp_path / 'templates.yaml'
    with open(template_path, 'w') as f:
        yaml.dump(templates, f)

    # Mock PROMPTS_DIR
    with patch('threat_model.core.config.PROMPTS_DIR', tmp_path):
        loaded_templates = generator._load_templates()
        # Verify all expected templates are present
        assert set(loaded_templates.keys()) == set(templates.keys())
        # Verify each template is a string
        assert all(isinstance(v, str) for v in loaded_templates.values())

def test_load_data(generator: ThreatModelGenerator, sample_data_dir: Dict[str, Path]) -> None:
    """Test data loading."""
    generator.load_data(
        sample_data_dir['mitre_path'],
        sample_data_dir['idp_path'],
        sample_data_dir['audit_path']
    )
    assert not generator.data_processor.mitre_data.empty
    assert not generator.data_processor.idp_data.empty
    assert not generator.data_processor.audit_data.empty

@patch('threat_model.core.generator.jinja2.Template')
def test_create_section(mock_template: Mock, generator: ThreatModelGenerator, sample_data_dir: Dict[str, Path]) -> None:
    """Test section creation."""
    # Load test data
    generator.load_data(
        sample_data_dir['mitre_path'],
        sample_data_dir['idp_path'],
        sample_data_dir['audit_path']
    )

    # Set up expected template data
    expected_content = "Rendered content"
    mock_template_instance = Mock()
    mock_template_instance.render.return_value = expected_content
    mock_template.return_value = mock_template_instance

    # Create section with technique ID
    section = generator._create_section(['T1110'])
    
    # Verify template was called with correct context
    mock_template_instance.render.assert_called_once()
    template_context = mock_template_instance.render.call_args[1]
    
    # Verify required fields are present and have correct types
    assert isinstance(template_context['section_title'], str)
    assert template_context['section_title'].startswith("Attack Vector Group:")
    
    assert isinstance(template_context['risk_level'], str)
    assert template_context['risk_level'] in ['Critical', 'High', 'Medium', 'Low']
    
    assert isinstance(template_context['impact'], str)
    assert template_context['impact'] in ['High', 'Medium']
    
    assert isinstance(template_context['likelihood'], str)
    assert template_context['likelihood'] in ['High', 'Medium', 'Low']
    
    assert isinstance(template_context['techniques'], list)
    assert len(template_context['techniques']) > 0
    technique = template_context['techniques'][0]
    assert all(key in technique for key in ['id', 'name', 'description', 'operations'])
    assert technique['id'] == 'T1110'
    
    assert isinstance(template_context['operations'], list)
    assert all(isinstance(op, dict) for op in template_context['operations'])
    if template_context['operations']:
        assert all(key in template_context['operations'][0] for key in ['operation', 'score', 'techniques'])
    
    assert isinstance(template_context['detection_strategy'], dict)
    assert all(key in template_context['detection_strategy'] for key in ['audit_events', 'correlation_rules', 'behavioral_analytics'])
    
    assert isinstance(template_context['controls'], dict)
    assert all(key in template_context['controls'] for key in ['preventive', 'detective'])
    
    # Verify result
    assert section == expected_content

def test_calculate_risk_level(generator: ThreatModelGenerator) -> None:
    """Test risk level calculation."""
    techniques = [
        {
            'id': 'T1110',
            'operations': [('op1', 0.5), ('op2', 0.7)]
        }
    ]
    risk_level = generator._calculate_risk_level(techniques)
    assert isinstance(risk_level, str)
    assert risk_level in ['Critical', 'High', 'Medium', 'Low']

def test_calculate_impact(generator: ThreatModelGenerator) -> None:
    """Test impact calculation."""
    techniques = [
        {
            'id': 'T1110',
            'description': 'Test with credentials and sensitive data'
        }
    ]
    impact = generator._calculate_impact(techniques)
    assert isinstance(impact, str)
    assert impact in ['High', 'Medium']

def test_calculate_likelihood(generator: ThreatModelGenerator) -> None:
    """Test likelihood calculation."""
    techniques = [
        {
            'id': 'T1110',
            'operations': [('op1', 0.5)] * 15
        }
    ]
    likelihood = generator._calculate_likelihood(techniques)
    assert isinstance(likelihood, str)
    assert likelihood in ['High', 'Medium', 'Low']

def test_get_combined_operations(generator: ThreatModelGenerator) -> None:
    """Test operation combination."""
    techniques = [
        {
            'id': 'T1110',
            'operations': [('op1', 0.5), ('op2', 0.7)]
        },
        {
            'id': 'T1078',
            'operations': [('op2', 0.8), ('op3', 0.6)]
        }
    ]
    combined = generator._get_combined_operations(techniques)
    assert isinstance(combined, list)
    assert all(isinstance(op, dict) for op in combined)
    assert all('operation' in op for op in combined)
    assert all('score' in op for op in combined)
    assert all('techniques' in op for op in combined)


def test_generate_threat_model(generator: ThreatModelGenerator, sample_data_dir: Dict[str, Path], tmp_path: Path) -> None:
    """Test threat model generation."""
    # Load test data
    generator.load_data(
        sample_data_dir['mitre_path'],
        sample_data_dir['idp_path'],
        sample_data_dir['audit_path']
    )

    # Set up test output directory
    output_file = tmp_path / 'threat_model.md'
    
    # Mock get_technique_groups to return test data
    with patch.object(generator.data_processor, 'get_technique_groups') as mock_get_groups:
        mock_get_groups.return_value = [['T1110']]  # Return a list with one group containing one technique
        
        # Mock section template and jinja2.Template
        with patch('threat_model.core.generator.jinja2.Template') as mock_template:
            mock_template_instance = Mock()
            mock_template_instance.render.return_value = "Rendered section content"
            mock_template.return_value = mock_template_instance
            
            # Generate threat model with custom output directory
            content = generator.generate_threat_model(output_dir=tmp_path)
            
            # Verify content structure
            assert isinstance(content, str)
            assert "Microsoft 365 and Entra ID Threat Model" in content
            assert "Rendered section content" in content
            
            # Verify file creation
            assert output_file.exists(), f"Output file was not created at {output_file}"
            assert output_file.is_file(), f"Output path exists but is not a file: {output_file}"
            
            # Verify file content
            file_content = output_file.read_text()
            assert file_content == content, "File content does not match generated content"

def test_create_detection_strategy(generator: ThreatModelGenerator) -> None:
    """Test detection strategy creation."""
    techniques = [
        {
            'id': 'T1110',
            'name': 'Brute Force',
            'operations': [('op1', 0.5), ('op2', 0.7)]
        }
    ]
    strategy = generator._create_detection_strategy(techniques)
    assert isinstance(strategy, dict)
    assert 'audit_events' in strategy
    assert 'correlation_rules' in strategy
    assert 'behavioral_analytics' in strategy

def test_create_controls(generator: ThreatModelGenerator) -> None:
    """Test security controls creation."""
    techniques = [
        {
            'id': 'T1110',
            'name': 'Brute Force',
            'description': 'Test description'
        }
    ]
    controls = generator._create_controls(techniques)
    assert isinstance(controls, dict)
    assert 'preventive' in controls
    assert 'detective' in controls
