"""Unit tests for the threat model generator module."""
import os
from pathlib import Path
import json
import pytest
from unittest.mock import Mock, patch, MagicMock
import yaml
from anthropic import Anthropic
from anthropic.types.messages.batch_create_params import Request

from threat_model.core.generator import ThreatModelGenerator
from threat_model.core.config import DEFAULT_MODEL, MAX_TOKENS

@pytest.fixture
def mock_anthropic():
    """Create a mock Anthropic client."""
    with patch('anthropic.Anthropic') as mock:
        yield mock

@pytest.fixture
def generator(mock_anthropic):
    """Create a ThreatModelGenerator instance for testing."""
    return ThreatModelGenerator(api_key="test-key")

@pytest.fixture
def sample_data_dir(tmp_path):
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
        'section_template': '# {section_title}\n{content}',
        'threat_model_template': '# {title}\n{overview}\n{sections}',
        'technique_model_template': '# Technique: {technique_name}\n{description}'
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

def test_init(generator):
    """Test generator initialization."""
    assert generator.client is not None
    assert generator.data_processor is not None
    assert isinstance(generator.templates, dict)

def test_load_templates(generator, tmp_path):
    """Test template loading."""
    # Create test templates
    templates = {
        'test_template': 'Test content: {variable}',
        'another_template': 'Another test: {data}'
    }
    template_path = tmp_path / 'templates.yaml'
    with open(template_path, 'w') as f:
        yaml.dump(templates, f)

    # Mock PROMPTS_DIR
    with patch('threat_model.core.config.PROMPTS_DIR', tmp_path):
        loaded_templates = generator._load_templates()
        assert loaded_templates == templates

def test_load_data(generator, sample_data_dir):
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
def test_create_section(mock_template, generator, sample_data_dir):
    """Test section creation."""
    # Load test data
    generator.load_data(
        sample_data_dir['mitre_path'],
        sample_data_dir['idp_path'],
        sample_data_dir['audit_path']
    )

    # Mock template rendering
    mock_template.return_value.render.return_value = "Rendered content"

    # Create section
    section = generator._create_section(['T1110'])
    assert section == "Rendered content"

def test_calculate_risk_level(generator):
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

def test_calculate_impact(generator):
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

def test_calculate_likelihood(generator):
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

def test_get_combined_operations(generator):
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

@patch('anthropic.Anthropic')
def test_create_batch_request(mock_anthropic, generator):
    """Test batch request creation."""
    request = generator._create_batch_request('T1110', 'test-id')
    assert isinstance(request, Request)
    assert request.custom_id == 'test-id'
    assert request.params.model == DEFAULT_MODEL
    assert request.params.max_tokens == MAX_TOKENS

@patch('threat_model.core.generator.time.sleep')
def test_generate_threat_model_batch(mock_sleep, generator, sample_data_dir, tmp_path):
    """Test batch threat model generation."""
    # Load test data
    generator.load_data(
        sample_data_dir['mitre_path'],
        sample_data_dir['idp_path'],
        sample_data_dir['audit_path']
    )

    # Mock batch processing
    mock_batch = MagicMock()
    mock_batch.id = 'test-batch'
    mock_batch.processing_status = 'ended'
    generator.client.messages.batches.create.return_value = mock_batch
    
    # Mock batch results
    mock_result = MagicMock()
    mock_result.result.type = 'succeeded'
    mock_result.result.message.content = [MagicMock(type='text', text='Test content')]
    mock_result.custom_id = 'technique_0'
    generator.client.messages.batches.results.return_value = [mock_result]

    # Generate batch threat model
    output_file = tmp_path / 'output.md'
    generator.generate_threat_model_batch(['Section 1'], output_file)
    
    assert output_file.exists()
    content = output_file.read_text()
    assert 'Microsoft 365 & Entra ID Threat Models' in content

def test_generate_threat_model(generator, sample_data_dir, tmp_path):
    """Test threat model generation."""
    # Load test data
    generator.load_data(
        sample_data_dir['mitre_path'],
        sample_data_dir['idp_path'],
        sample_data_dir['audit_path']
    )

    # Mock output directory
    with patch('threat_model.core.config.OUTPUT_DIR', tmp_path):
        content = generator.generate_threat_model()
        assert isinstance(content, str)
        assert (tmp_path / 'threat_model.md').exists()

def test_create_detection_strategy(generator):
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

def test_create_controls(generator):
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