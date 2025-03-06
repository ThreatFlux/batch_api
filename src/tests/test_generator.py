"""Unit tests for the threat model generator module."""

from pathlib import Path
from typing import Dict, Generator
from unittest.mock import Mock, patch, MagicMock

import pandas as pd
import pytest
import yaml
from threat_model.core.generator import ThreatModelGenerator

# Test data
test_template = {
    "system_prompt": "System prompt content",
    "system_prompt_summary": "System prompt summary",
    "technique_model_template": "Technique model template",
    "section_template": "Section template",
    "correlation_prompt": "Correlation prompt",
    "group_prompt": "Group prompt",
    "validation_prompt": "Validation prompt",
}

# Disable specific pylint warnings that are common in pytest files
# pylint: disable=redefined-outer-name
# pylint: disable=missing-function-docstring


@pytest.fixture
def mock_anthropic() -> Generator[Mock, None, None]:
    """Create a mock Anthropic client."""
    with patch("anthropic.Anthropic") as mock:
        yield mock


@pytest.fixture
def generator(mock_anthropic: Mock) -> ThreatModelGenerator:  # pylint: disable=unused-argument
    """Create a ThreatModelGenerator instance for testing.

    Args:
        mock_anthropic: Mock Anthropic client

    Returns:
        ThreatModelGenerator: Configured test generator
    """
    return ThreatModelGenerator(api_key="test-key")


@pytest.fixture
def sample_data_dir_test(tmp_path: Path) -> Dict[str, Path]:
    """Create sample data files for testing.

    Args:
        tmp_path: Pytest temporary path fixture

    Returns:
        Dict[str, Path]: Dictionary of test file paths
    """
    # Create MITRE data
    mitre_data = """TID,Tactic,Technique,Description
T1110,Initial Access,Brute Force,Adversaries may attempt brute force
T1078,Defense Evasion,Valid Accounts,Adversaries may obtain credentials"""
    mitre_path = tmp_path / "mitre.csv"
    mitre_path.write_text(mitre_data)

    # Create IDP data
    idp_data = """TID,Tactic,Technique,Description
T1110,Initial Access,Brute Force,IDP brute force description
T1078,Defense Evasion,Valid Accounts,IDP valid accounts description"""
    idp_path = tmp_path / "idp.csv"
    idp_path.write_text(idp_data)

    # Create audit data
    audit_data = """FriendlyName,Operation,Description
Failed Login,UserLoginFailed,User login attempt failed
Account Access,UserLoggedIn,User successfully logged in"""
    audit_path = tmp_path / "audit.csv"
    audit_path.write_text(audit_data)

    # Create templates
    templates = test_template
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    template_path = template_dir / "templates.yaml"
    with open(template_path, "w", encoding="utf-8") as f:
        yaml.dump(templates, f)

    return {"mitre_path": mitre_path, "idp_path": idp_path, "audit_path": audit_path, "template_path": template_path}


def test_init(generator: ThreatModelGenerator) -> None:
    """Test generator initialization."""
    assert generator.client is not None
    assert generator.data_processor is not None
    assert isinstance(generator.templates, dict)


def test_init_error_handling() -> None:
    """Test error handling during initialization."""
    with pytest.raises(ValueError, match="API key cannot be empty"):
        ThreatModelGenerator(api_key="")


def test_load_templates_error(mock_anthropic: Mock, tmp_path: Path) -> None:  # pylint: disable=unused-argument
    """Test template loading error handling."""
    # Create empty directory to ensure no templates.yaml exists
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    # Mock the template path resolution
    mock_path = MagicMock()
    mock_path.configure_mock(
        **{"exists.return_value": False, "__str__.return_value": str(empty_dir / "templates.yaml")}
    )

    # Mock both the PROMPTS_DIR and the Path operations
    with patch("threat_model.core.config.PROMPTS_DIR", empty_dir):
        with patch.object(Path, "__truediv__", return_value=mock_path):
            with patch.object(mock_path, "exists", return_value=False):
                with pytest.raises(FileNotFoundError, match="Templates file not found"):
                    ThreatModelGenerator(api_key="test-key")


def test_load_templates(generator: ThreatModelGenerator, tmp_path: Path) -> None:
    """Test template loading."""
    # pylint: disable=protected-access
    # Create test templates with expected structure
    templates = test_template
    template_path = tmp_path / "templates.yaml"
    with open(template_path, "w", encoding="utf-8") as f:
        yaml.dump(templates, f)

    # Mock PROMPTS_DIR
    with patch("threat_model.core.config.PROMPTS_DIR", tmp_path):
        loaded_templates = generator._load_templates()
        # Verify all expected templates are present
        assert set(loaded_templates.keys()) == set(templates.keys())
        # Verify each template is a string
        assert all(isinstance(v, str) for v in loaded_templates.values())


def test_load_data(generator: ThreatModelGenerator, sample_data_dir_test: Dict[str, Path]) -> None:
    """Test data loading."""
    generator.load_data(
        sample_data_dir_test["mitre_path"], sample_data_dir_test["idp_path"], sample_data_dir_test["audit_path"]
    )
    assert not generator.data_processor.mitre_data.empty
    assert not generator.data_processor.idp_data.empty
    assert not generator.data_processor.audit_data.empty


def test_load_data_error(generator: ThreatModelGenerator, tmp_path: Path) -> None:
    """Test data loading error handling."""
    with pytest.raises(FileNotFoundError):
        generator.load_data(tmp_path / "nonexistent.csv", tmp_path / "nonexistent.csv", tmp_path / "nonexistent.csv")


@patch("threat_model.core.generator.jinja2.Template")
def test_create_section(
    mock_template: Mock, generator: ThreatModelGenerator, sample_data_dir_test: Dict[str, Path]
) -> None:
    """Test section creation."""
    # pylint: disable=protected-access
    # Load test data
    generator.load_data(
        sample_data_dir_test["mitre_path"], sample_data_dir_test["idp_path"], sample_data_dir_test["audit_path"]
    )

    # Set up expected template data
    expected_content = "Rendered content"
    mock_template_instance = Mock()
    mock_template_instance.render.return_value = expected_content
    mock_template.return_value = mock_template_instance

    # Create section with technique ID
    section = generator._create_section(["T1110"])

    # Verify template was called with correct context
    mock_template_instance.render.assert_called_once()
    template_context = mock_template_instance.render.call_args[1]

    # Verify required fields are present and have correct types
    assert isinstance(template_context["section_title"], str)
    assert template_context["section_title"].startswith("Attack Vector Group:")

    assert isinstance(template_context["risk_level"], str)
    assert template_context["risk_level"] in ["Critical", "High", "Medium", "Low"]

    assert isinstance(template_context["impact"], str)
    assert template_context["impact"] in ["High", "Medium"]

    assert isinstance(template_context["likelihood"], str)
    assert template_context["likelihood"] in ["High", "Medium", "Low"]

    assert isinstance(template_context["techniques"], list)
    assert len(template_context["techniques"]) > 0
    technique = template_context["techniques"][0]
    assert all(key in technique for key in ["id", "name", "description", "operations"])
    assert technique["id"] == "T1110"

    assert isinstance(template_context["operations"], list)
    assert all(isinstance(op, dict) for op in template_context["operations"])
    if template_context["operations"]:
        assert all(key in template_context["operations"][0] for key in ["operation", "score", "techniques"])

    assert isinstance(template_context["detection_strategy"], dict)
    assert all(
        key in template_context["detection_strategy"]
        for key in ["audit_events", "correlation_rules", "behavioral_analytics"]
    )

    assert isinstance(template_context["controls"], dict)
    assert all(key in template_context["controls"] for key in ["preventive", "detective"])

    # Verify result
    assert section == expected_content


def test_calculate_risk_level(generator: ThreatModelGenerator) -> None:
    """Test risk level calculation."""
    # pylint: disable=protected-access
    # Test Critical risk level
    techniques = [{"id": "T1110", "operations": [("op1", 0.5)] * 16}]
    assert generator._calculate_risk_level(techniques) == "Critical"

    # Test High risk level
    techniques = [{"id": "T1110", "operations": [("op1", 0.5)] * 11}]
    assert generator._calculate_risk_level(techniques) == "High"

    # Test Medium risk level
    techniques = [{"id": "T1110", "operations": [("op1", 0.5)] * 6}]
    assert generator._calculate_risk_level(techniques) == "Medium"

    # Test Low risk level
    techniques = [{"id": "T1110", "operations": [("op1", 0.5)] * 2}]
    assert generator._calculate_risk_level(techniques) == "Low"


def test_calculate_impact(generator: ThreatModelGenerator) -> None:
    """Test impact calculation."""
    # pylint: disable=protected-access
    # Test High impact
    techniques = [{"id": "T1110", "description": "Test with credentials and sensitive data"}]
    assert generator._calculate_impact(techniques) == "High"

    # Test Medium impact
    techniques = [{"id": "T1110", "description": "Test without high-impact keywords"}]
    assert generator._calculate_impact(techniques) == "Medium"


def test_calculate_likelihood(generator: ThreatModelGenerator) -> None:
    """Test likelihood calculation."""
    # pylint: disable=protected-access
    # Test High likelihood
    techniques = [{"id": "T1110", "operations": [("op1", 0.5)] * 21}]
    assert generator._calculate_likelihood(techniques) == "High"

    # Test Medium likelihood
    techniques = [{"id": "T1110", "operations": [("op1", 0.5)] * 11}]
    assert generator._calculate_likelihood(techniques) == "Medium"

    # Test Low likelihood
    techniques = [{"id": "T1110", "operations": [("op1", 0.5)] * 5}]
    assert generator._calculate_likelihood(techniques) == "Low"


def test_get_combined_operations(generator: ThreatModelGenerator) -> None:
    """Test operation combination."""
    # pylint: disable=protected-access
    techniques = [
        {"id": "T1110", "operations": [("op1", 0.5), ("op2", 0.7)]},
        {"id": "T1078", "operations": [("op2", 0.8), ("op3", 0.6)]},
    ]
    combined = generator._get_combined_operations(techniques)
    assert isinstance(combined, list)
    assert all(isinstance(op, dict) for op in combined)
    assert all("operation" in op for op in combined)
    assert all("score" in op for op in combined)
    assert all("techniques" in op for op in combined)
    # Verify operations are sorted by score
    scores = [op["score"] for op in combined]
    assert scores == sorted(scores, reverse=True)


def test_generate_threat_model(
    generator: ThreatModelGenerator, sample_data_dir_test: Dict[str, Path], tmp_path: Path
) -> None:
    """Test threat model generation."""
    # Load test data
    generator.load_data(
        sample_data_dir_test["mitre_path"], sample_data_dir_test["idp_path"], sample_data_dir_test["audit_path"]
    )

    # Set up test output directory
    output_file = tmp_path / "threat_model.md"

    # Mock get_technique_groups to return test data
    with patch.object(generator.data_processor, "get_technique_groups") as mock_get_groups:
        mock_get_groups.return_value = [["T1110"]]  # Return a list with one group containing one technique

        # Mock section template and jinja2.Template
        with patch("threat_model.core.generator.jinja2.Template") as mock_template:
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


def test_generate_threat_model_io_error(
    generator: ThreatModelGenerator, sample_data_dir_test: Dict[str, Path], tmp_path: Path
) -> None:
    """Test threat model generation IO error handling."""
    # Load test data
    generator.load_data(
        sample_data_dir_test["mitre_path"], sample_data_dir_test["idp_path"], sample_data_dir_test["audit_path"]
    )

    # Mock write_text to raise IOError
    with patch.object(Path, "write_text", side_effect=IOError("Test IO error")):
        with pytest.raises(IOError, match="Failed to write output file"):
            generator.generate_threat_model(output_dir=tmp_path)


def test_generate_threat_model_batch(
    generator: ThreatModelGenerator, sample_data_dir_test: Dict[str, Path], tmp_path: Path
) -> None:
    """Test batch threat model generation."""
    # Load test data
    generator.load_data(
        sample_data_dir_test["mitre_path"], sample_data_dir_test["idp_path"], sample_data_dir_test["audit_path"]
    )

    # Mock batch processor
    with patch.object(generator.batch_processor, "generate_threat_models") as mock_generate:
        generator.generate_threat_model_batch(["section1"], str(tmp_path / "output.md"))
        mock_generate.assert_called_once()


def test_generate_threat_model_batch_error(
    generator: ThreatModelGenerator, sample_data_dir_test: Dict[str, Path]
) -> None:
    """Test batch threat model generation error handling."""
    # Load test data first
    generator.load_data(
        sample_data_dir_test["mitre_path"], sample_data_dir_test["idp_path"], sample_data_dir_test["audit_path"]
    )

    # Test value error with empty data first
    generator.data_processor.mitre_data = pd.DataFrame(columns=["TID", "Tactic", "Technique", "Description"])
    with pytest.raises(ValueError, match="No MITRE techniques found in data"):
        generator.generate_threat_model_batch(["section1"], "output.md")

    # Restore test data
    generator.load_data(
        sample_data_dir_test["mitre_path"], sample_data_dir_test["idp_path"], sample_data_dir_test["audit_path"]
    )

    # Mock the batch processor's wait_for_batch_completion to avoid timeouts
    with patch.object(generator.batch_processor, "_wait_for_batch_completion"):
        # Test file not found error
        with pytest.raises(FileNotFoundError):
            generator.generate_threat_model_batch(["section1"], "nonexistent/path/output.md")

        # Test IO error
        with patch.object(generator.batch_processor, "generate_threat_models", side_effect=IOError("Test IO error")):
            with pytest.raises(IOError):
                generator.generate_threat_model_batch(["section1"], "output.md")


def test_create_detection_strategy(generator: ThreatModelGenerator) -> None:
    """Test detection strategy creation."""
    # pylint: disable=protected-access
    techniques = [{"id": "T1110", "name": "Brute Force", "operations": [("op1", 0.5), ("op2", 0.7)]}]
    strategy = generator._create_detection_strategy(techniques)
    assert isinstance(strategy, dict)
    assert "audit_events" in strategy
    assert "correlation_rules" in strategy
    assert "behavioral_analytics" in strategy
    # Verify correlation rules structure
    assert len(strategy["correlation_rules"]) > 0
    rule = strategy["correlation_rules"][0]
    assert all(key in rule for key in ["name", "description", "operations", "threshold", "window"])


def test_create_controls(generator: ThreatModelGenerator) -> None:
    """Test security controls creation."""
    # pylint: disable=protected-access
    techniques = [{"id": "T1110", "name": "Brute Force", "description": "Test description"}]
    controls = generator._create_controls(techniques)
    assert isinstance(controls, dict)
    assert "preventive" in controls
    assert "detective" in controls
    # Verify control structure
    assert len(controls["preventive"]) > 0
    control = controls["preventive"][0]
    assert all(key in control for key in ["name", "description", "implementation"])
