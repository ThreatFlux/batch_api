"""Unit tests for the data processor module."""

import pandas as pd
import pytest
from threat_model.core.data_processor import DataProcessor
from threat_model.core.config import CSV_SETTINGS


@pytest.fixture
def data_processor():
    """Create a DataProcessor instance for testing."""
    return DataProcessor()


@pytest.fixture
def sample_data_dir(tmp_path):
    """Create sample CSV files for testing."""
    # Create MITRE data
    mitre_data = pd.DataFrame(
        {
            "TID": ["T1110", "T1078"],
            "Tactic": ["Initial Access", "Defense Evasion"],
            "Technique": ["Brute Force", "Valid Accounts"],
            "Description": [
                "Adversaries may attempt to gain access through brute force.",
                "Adversaries may obtain and abuse credentials of existing accounts.",
            ],
        }
    )
    mitre_path = tmp_path / "mitre.csv"
    mitre_data.to_csv(mitre_path, index=False)

    # Create IDP data
    idp_data = pd.DataFrame(
        {
            "TID": ["T1110", "T1078"],
            "Tactic": ["Initial Access", "Defense Evasion"],
            "Technique": ["Brute Force", "Valid Accounts"],
            "Description": ["IDP specific brute force description.", "IDP specific valid accounts description."],
        }
    )
    idp_path = tmp_path / "idp.csv"
    idp_data.to_csv(idp_path, index=False)

    # Create audit data
    audit_data = pd.DataFrame(
        {
            "FriendlyName": ["Failed Login", "Account Access"],
            "Operation": ["UserLoginFailed", "UserLoggedIn"],
            "Description": [
                "User login attempt failed due to invalid credentials.",
                "User successfully logged in to the system.",
            ],
        }
    )
    audit_path = tmp_path / "audit.csv"
    audit_data.to_csv(audit_path, index=False)

    return {"mitre_path": mitre_path, "idp_path": idp_path, "audit_path": audit_path}


def test_load_csv_mitre(data_processor, sample_data_dir):
    """Test loading MITRE CSV file."""
    data_processor.load_csv(sample_data_dir["mitre_path"], "mitre")
    assert not data_processor.mitre_data.empty
    assert len(data_processor.mitre_data) == 2
    assert all(col in data_processor.mitre_data.columns for col in CSV_SETTINGS["mitre"]["required_columns"])


def test_load_csv_idp(data_processor, sample_data_dir):
    """Test loading IDP CSV file."""
    data_processor.load_csv(sample_data_dir["idp_path"], "idp")
    assert not data_processor.idp_data.empty
    assert len(data_processor.idp_data) == 2
    assert all(col in data_processor.idp_data.columns for col in CSV_SETTINGS["idp"]["required_columns"])


def test_load_csv_audit(data_processor, sample_data_dir):
    """Test loading audit CSV file."""
    data_processor.load_csv(sample_data_dir["audit_path"], "audit")
    assert not data_processor.audit_data.empty
    assert len(data_processor.audit_data) == 2
    assert all(col in data_processor.audit_data.columns for col in CSV_SETTINGS["audit"]["required_columns"])


def test_load_csv_invalid_file(data_processor, tmp_path):
    """Test loading invalid CSV file."""
    invalid_path = tmp_path / "invalid.csv"
    with open(invalid_path, "w") as f:
        f.write("invalid,csv,file\n")

    with pytest.raises(ValueError):
        data_processor.load_csv(invalid_path, "mitre")


def test_correlate_techniques_with_operations(data_processor, sample_data_dir):
    """Test correlation between techniques and operations."""
    # Load test data
    data_processor.load_csv(sample_data_dir["mitre_path"], "mitre")
    data_processor.load_csv(sample_data_dir["idp_path"], "idp")
    data_processor.load_csv(sample_data_dir["audit_path"], "audit")

    # Perform correlation
    correlation_matrix = data_processor.correlate_techniques_with_operations()

    # Verify correlation results
    assert isinstance(correlation_matrix, dict)
    assert len(correlation_matrix) > 0
    for technique_id, correlations in correlation_matrix.items():
        verify_results(correlations)


def test_get_related_techniques(data_processor, sample_data_dir):
    """Test finding related techniques."""
    # Load and correlate data
    data_processor.load_csv(sample_data_dir["mitre_path"], "mitre")
    data_processor.load_csv(sample_data_dir["idp_path"], "idp")
    data_processor.load_csv(sample_data_dir["audit_path"], "audit")
    data_processor.correlate_techniques_with_operations()

    # Get related techniques
    related = data_processor.get_related_techniques("T1110")

    # Verify results
    verify_results(related)


def verify_results(related):
    """Verify related techniques results.
    Args:
        related: List of related techniques or operations with similarity scores
    """
    assert isinstance(related, list)
    for value_to_check in related:
        assert isinstance(value_to_check, tuple)
        assert len(value_to_check) == 2
        assert isinstance(value_to_check[0], str)
        assert isinstance(value_to_check[1], float)
        assert 0 <= value_to_check[1] <= 1


def test_get_technique_groups(data_processor, sample_data_dir):
    """Test grouping related techniques."""
    # Load and correlate data
    data_processor.load_csv(sample_data_dir["mitre_path"], "mitre")
    data_processor.load_csv(sample_data_dir["idp_path"], "idp")
    data_processor.load_csv(sample_data_dir["audit_path"], "audit")
    data_processor.correlate_techniques_with_operations()

    # Get technique groups
    groups = data_processor.get_technique_groups()

    # Verify groups
    assert isinstance(groups, list)
    for group in groups:
        assert isinstance(group, list)
        assert all(isinstance(tid, str) for tid in group)


def test_calculate_correlation_score(data_processor):
    """Test correlation score calculation."""
    # Create test data
    technique = pd.Series({"Technique": "Brute Force", "Description": "Test brute force attack description"})
    operation = pd.Series({"Operation": "UserLoginFailed", "Description": "Failed login attempt"})
    similarity_score = 0.5

    # Calculate score
    score = data_processor._calculate_correlation_score(technique, operation, similarity_score)

    # Verify score
    assert isinstance(score, float)
    assert 0 <= score <= 1


def test_preprocess_dataframe(data_processor):
    """Test DataFrame preprocessing."""
    # Create test DataFrame
    df = pd.DataFrame({"col1": [" test ", "value ", None], "col2": ["data", None, "test "]})

    # Preprocess DataFrame
    processed_df = data_processor._preprocess_dataframe(df)

    # Verify preprocessing
    assert processed_df["col1"].isnull().sum() == 0
    assert processed_df["col2"].isnull().sum() == 0
    assert all(isinstance(val, str) for val in processed_df["col1"])
    assert all(isinstance(val, str) for val in processed_df["col2"])
    assert all(val == val.strip() for val in processed_df["col1"])
    assert all(val == val.strip() for val in processed_df["col2"])
