"""Unit tests for the main application module."""
import os
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock
from threat_model.__main__ import parse_args, main

def test_parse_args():
    """Test command line argument parsing."""
    # Test default arguments
    with patch('sys.argv', ['threat_model']):
        args = parse_args()
        assert args.mitre_path == "office_suite_description_mitre_dump.csv"
        assert args.idp_path == "idp_description_mitre_dump.csv"
        assert args.audit_path == "audit_operations.csv"
        assert args.output == "threat_model.md"
        assert not args.batch
        assert args.sections == ["Authentication Mechanisms", 
                               "Data Access Controls",
                               "Application Security"]

    # Test custom arguments
    test_args = [
        'threat_model',
        '--mitre-path', 'custom_mitre.csv',
        '--idp-path', 'custom_idp.csv',
        '--audit-path', 'custom_audit.csv',
        '--output', 'custom_output.md',
        '--batch',
        '--sections', 'Section1', 'Section2'
    ]
    with patch('sys.argv', test_args):
        args = parse_args()
        assert args.mitre_path == "custom_mitre.csv"
        assert args.idp_path == "custom_idp.csv"
        assert args.audit_path == "custom_audit.csv"
        assert args.output == "custom_output.md"
        assert args.batch
        assert args.sections == ["Section1", "Section2"]

@patch('threat_model.__main__.ThreatModelGenerator')
@patch('threat_model.__main__.load_dotenv')
def test_main_success(mock_load_dotenv, mock_generator):
    """Test successful execution of main function."""
    # Mock environment variables
    mock_env = {
        'ANTHROPIC_API_KEY': 'test-key'
    }
    with patch.dict(os.environ, mock_env):
        # Mock generator instance
        mock_generator_instance = MagicMock()
        mock_generator.return_value = mock_generator_instance

        # Test default execution
        with patch('sys.argv', ['threat_model']):
            main()
            
            # Verify dotenv was loaded
            mock_load_dotenv.assert_called_once()
            
            # Verify generator was initialized
            mock_generator.assert_called_once_with(api_key='test-key')
            
            # Verify data was loaded
            mock_generator_instance.load_data.assert_called_once()
            
            # Verify threat model was generated
            assert mock_generator_instance.generate_threat_model.called or \
                   mock_generator_instance.generate_threat_model_batch.called

@patch('threat_model.__main__.ThreatModelGenerator')
@patch('threat_model.__main__.load_dotenv')
def test_main_batch_mode(mock_load_dotenv, mock_generator):
    """Test main function in batch mode."""
    # Mock environment variables
    mock_env = {
        'ANTHROPIC_API_KEY': 'test-key'
    }
    with patch.dict(os.environ, mock_env):
        # Mock generator instance
        mock_generator_instance = MagicMock()
        mock_generator.return_value = mock_generator_instance

        # Test batch execution
        test_args = [
            'threat_model',
            '--batch',
            '--sections', 'Section1', 'Section2'
        ]
        with patch('sys.argv', test_args):
            main()
            
            # Verify batch generation was called
            mock_generator_instance.generate_threat_model_batch.assert_called_once()
            assert not mock_generator_instance.generate_threat_model.called

@patch('threat_model.__main__.load_dotenv')
def test_main_missing_api_key(mock_load_dotenv):
    """Test main function with missing API key."""
    # Mock environment without API key
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError) as exc_info:
            main()
        assert "ANTHROPIC_API_KEY environment variable not set" in str(exc_info.value)

@patch('threat_model.__main__.ThreatModelGenerator')
@patch('threat_model.__main__.load_dotenv')
def test_main_generator_error(mock_load_dotenv, mock_generator):
    """Test main function handling generator errors."""
    # Mock environment variables
    mock_env = {
        'ANTHROPIC_API_KEY': 'test-key'
    }
    with patch.dict(os.environ, mock_env):
        # Mock generator to raise an error
        mock_generator_instance = MagicMock()
        mock_generator_instance.load_data.side_effect = Exception("Test error")
        mock_generator.return_value = mock_generator_instance

        # Test error handling
        with pytest.raises(Exception) as exc_info:
            main()
        assert "Test error" in str(exc_info.value)

@patch('threat_model.__main__.ThreatModelGenerator')
@patch('threat_model.__main__.load_dotenv')
def test_main_custom_paths(mock_load_dotenv, mock_generator):
    """Test main function with custom file paths."""
    # Mock environment variables
    mock_env = {
        'ANTHROPIC_API_KEY': 'test-key'
    }
    with patch.dict(os.environ, mock_env):
        # Mock generator instance
        mock_generator_instance = MagicMock()
        mock_generator.return_value = mock_generator_instance

        # Test with custom paths
        test_args = [
            'threat_model',
            '--mitre-path', 'custom_mitre.csv',
            '--idp-path', 'custom_idp.csv',
            '--audit-path', 'custom_audit.csv',
            '--output', 'custom_output.md'
        ]
        with patch('sys.argv', test_args):
            main()
            
            # Verify correct paths were used
            call_args = mock_generator_instance.load_data.call_args[1]
            assert 'custom_mitre.csv' in str(call_args['mitre_path'])
            assert 'custom_idp.csv' in str(call_args['idp_path'])
            assert 'custom_audit.csv' in str(call_args['audit_path'])