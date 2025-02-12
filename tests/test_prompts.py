"""Unit tests for the prompts module."""
import os
from pathlib import Path
import pytest
from threat_model.prompts import TEMPLATES_FILE

def test_templates_file_exists() -> None:
    """Test that the templates file exists at the expected path."""
    assert TEMPLATES_FILE.exists(), f"Templates file not found at {TEMPLATES_FILE}"
    assert TEMPLATES_FILE.is_file(), f"{TEMPLATES_FILE} exists but is not a file"

def test_templates_file_path() -> None:
    """Test that the templates file path is correctly configured."""
    expected_path = Path(__file__).parent.parent / "src" / "threat_model" / "prompts" / "templates.yaml"
    assert TEMPLATES_FILE.name == "templates.yaml"
    assert TEMPLATES_FILE.suffix == ".yaml"
    assert os.path.normpath(TEMPLATES_FILE) == os.path.normpath(expected_path)

def test_templates_file_readable() -> None:
    """Test that the templates file is readable."""
    assert os.access(TEMPLATES_FILE, os.R_OK), f"Templates file at {TEMPLATES_FILE} is not readable"

def test_templates_file_in_package() -> None:
    """Test that the templates file is in the correct package directory."""
    assert "threat_model" in str(TEMPLATES_FILE.parent)
    assert "prompts" in str(TEMPLATES_FILE.parent)
