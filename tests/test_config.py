"""Unit tests for the configuration module."""

import os
from pathlib import Path
import pytest
from threat_model.core import config


def test_project_paths():
    """Test project path configurations."""
    assert isinstance(config.PROJECT_ROOT, Path)
    assert isinstance(config.DATA_DIR, Path)
    assert isinstance(config.PROMPTS_DIR, Path)
    assert isinstance(config.OUTPUT_DIR, Path)
    assert isinstance(config.CACHE_DIR, Path)


def test_model_settings():
    """Test model configuration settings."""
    assert isinstance(config.DEFAULT_MODEL, str)
    assert isinstance(config.MAX_TOKENS, int)
    assert isinstance(config.BATCH_SIZE, int)
    assert config.MAX_TOKENS > 0
    assert config.BATCH_SIZE > 0


def test_csv_settings():
    """Test CSV configuration settings."""
    required_settings = ["required_columns", "index_column", "encoding"]
    file_types = ["mitre", "idp", "audit"]

    assert isinstance(config.CSV_SETTINGS, dict)

    for file_type in file_types:
        assert file_type in config.CSV_SETTINGS
        settings = config.CSV_SETTINGS[file_type]

        # Check required settings exist
        for setting in required_settings:
            assert setting in settings

        # Check required columns
        assert isinstance(settings["required_columns"], list)
        assert len(settings["required_columns"]) > 0
        assert all(isinstance(col, str) for col in settings["required_columns"])

        # Check index column
        assert isinstance(settings["index_column"], str)

        # Check encoding
        assert isinstance(settings["encoding"], str)
        assert settings["encoding"].lower() == "utf-8"


def test_correlation_weights():
    """Test correlation weight settings."""
    required_weights = ["exact_match", "partial_match", "description_similarity"]

    assert isinstance(config.CORRELATION_WEIGHTS, dict)

    # Check required weights exist
    for weight in required_weights:
        assert weight in config.CORRELATION_WEIGHTS
        assert isinstance(config.CORRELATION_WEIGHTS[weight], float)
        assert 0 <= config.CORRELATION_WEIGHTS[weight] <= 1


def test_logging_settings():
    """Test logging configuration."""
    assert isinstance(config.LOG_FORMAT, str)
    assert isinstance(config.LOG_LEVEL, str)
    assert config.LOG_LEVEL in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def test_file_patterns():
    """Test file pattern settings."""
    assert isinstance(config.MITRE_FILE_PATTERN, str)
    assert isinstance(config.AUDIT_FILE_PATTERN, str)
    assert "*" in config.MITRE_FILE_PATTERN
    assert ".csv" in config.MITRE_FILE_PATTERN.lower()
    assert ".csv" in config.AUDIT_FILE_PATTERN.lower()


def test_output_settings():
    """Test output configuration settings."""
    assert isinstance(config.THREAT_MODEL_TEMPLATE, str)
    assert isinstance(config.OUTPUT_FILE, str)
    assert ".md" in config.OUTPUT_FILE.lower()


def test_cache_settings():
    """Test cache configuration settings."""
    assert isinstance(config.CACHE_EXPIRY, int)
    assert config.CACHE_EXPIRY > 0


def test_api_settings():
    """Test API configuration settings."""
    assert isinstance(config.API_RETRY_ATTEMPTS, int)
    assert isinstance(config.API_RETRY_DELAY, int)
    assert config.API_RETRY_ATTEMPTS > 0
    assert config.API_RETRY_DELAY > 0


def test_path_relationships():
    """Test relationships between path configurations."""
    # DATA_DIR should be under PROJECT_ROOT
    assert config.PROJECT_ROOT in config.DATA_DIR.parents

    # PROMPTS_DIR should be under PROJECT_ROOT
    assert config.PROJECT_ROOT in config.PROMPTS_DIR.parents

    # OUTPUT_DIR should be under PROJECT_ROOT
    assert config.PROJECT_ROOT in config.OUTPUT_DIR.parents

    # CACHE_DIR should be under PROJECT_ROOT
    assert config.PROJECT_ROOT in config.CACHE_DIR.parents
