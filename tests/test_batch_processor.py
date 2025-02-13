"""Unit tests for the batch processor module."""

import json
from pathlib import Path
from typing import Any, Dict, Generator
import pandas as pd
import pytest
from anthropic import Anthropic, RateLimitError
from unittest.mock import MagicMock, patch
from anthropic.types import Message, MessageStreamEvent
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages.batch_create_params import Request
from threat_model.core.batch_processor import BatchProcessor
from threat_model.core.data_processor import DataProcessor
from threat_model.core.config import DEFAULT_MODEL, MAX_TOKENS


class MockAnthropicClient:
    """Mock Anthropic client for testing."""

    def __init__(self) -> None:
        """Initialize mock client."""
        self.messages = MockMessages()


class MockMessages:
    """Mock messages class for testing."""

    def __init__(self) -> None:
        """Initialize mock messages."""
        self.batches = MockBatches()


class MockBatches:
    """Mock batches class for testing."""

    def __init__(self) -> None:
        """Initialize mock batches."""
        self.batch_id = "test_batch_123"
        self.processing_status = "ended"

    def create(self, requests: list[Request]) -> Any:
        """Mock batch creation."""
        return type("MockBatch", (), {"id": self.batch_id})

    def retrieve(self, batch_id: str) -> Any:
        """Mock batch status retrieval."""
        return type("MockStatus", (), {"processing_status": self.processing_status})

    def results(self, batch_id: str) -> Generator[Any, None, None]:
        """Mock batch results."""
        yield type(
            "MockResult",
            (),
            {
                "custom_id": "technique_0",
                "result": type(
                    "MockResultType",
                    (),
                    {
                        "type": "succeeded",
                        "message": type(
                            "MockMessage",
                            (),
                            {
                                "content": [
                                    type("MockContent", (), {"type": "text", "text": "# Test Threat Model Content"})
                                ]
                            },
                        ),
                    },
                ),
            },
        )


@pytest.fixture
def mock_client() -> MockAnthropicClient:
    """Create a mock Anthropic client."""
    return MockAnthropicClient()


@pytest.fixture
def data_processor(tmp_path: Path) -> DataProcessor:
    """Create a DataProcessor instance with test data."""
    dp = DataProcessor()

    # Create test MITRE data
    mitre_data = {
        "TID": ["T1110"],
        "Tactic": ["Initial Access"],
        "Technique": ["Brute Force"],
        "Description": ["Test description"],
    }
    mitre_path = tmp_path / "mitre.csv"
    dp.mitre_data = pd.DataFrame(mitre_data)

    # Create test audit data
    audit_data = {
        "Operation": ["UserLoginFailed"],
        "FriendlyName": ["Failed Login"],
        "Description": ["Test login failure"],
    }
    dp.audit_data = pd.DataFrame(audit_data)

    return dp


@pytest.fixture
def batch_processor(mock_client: MockAnthropicClient, data_processor: DataProcessor) -> BatchProcessor:
    """Create a BatchProcessor instance for testing."""
    return BatchProcessor(mock_client, data_processor)


def test_init(mock_client: MockAnthropicClient, data_processor: DataProcessor) -> None:
    """Test BatchProcessor initialization."""
    processor = BatchProcessor(mock_client, data_processor)
    assert processor.client == mock_client
    assert processor.data_processor == data_processor


def test_create_batch_request(batch_processor: BatchProcessor) -> None:
    """Test creation of batch request."""
    request = batch_processor._create_batch_request("T1110", "test_id")

    assert isinstance(request, dict)
    assert request["custom_id"] == "test_id"
    assert isinstance(request["params"], dict)
    assert request["params"]["model"] == DEFAULT_MODEL
    assert request["params"]["max_tokens"] == MAX_TOKENS
    assert isinstance(request["params"]["system"], str)
    assert isinstance(request["params"]["messages"], list)


def test_process_batch(batch_processor: BatchProcessor) -> None:
    """Test processing a batch of technique IDs."""
    technique_ids = ["T1110"]
    result = batch_processor.process_batch(technique_ids, 0)

    assert isinstance(result, dict)
    assert "technique_0" in result
    assert result["technique_0"].startswith("# Test Threat Model Content")


def test_process_batch_empty(batch_processor: BatchProcessor) -> None:
    """Test processing an empty batch."""
    result = batch_processor.process_batch([], 0)
    assert isinstance(result, dict)
    assert len(result) == 0


def test_process_batch_request_error(batch_processor: BatchProcessor, data_processor: DataProcessor) -> None:
    """Test handling errors during batch request creation."""
    # Simulate error by using invalid technique ID
    result = batch_processor.process_batch(["INVALID_ID"], 0)
    assert isinstance(result, dict)
    assert len(result) == 0


@patch("time.sleep")
def test_process_batch_rate_limit(mock_sleep: MagicMock, batch_processor: BatchProcessor) -> None:
    """Test handling rate limit errors during batch processing."""
    # Replace the client's batches with a mock that raises RateLimitError
    original_batches = batch_processor.client.messages.batches
    try:
        mock_batches = MagicMock()
        mock_batches.create.side_effect = RateLimitError(
            response=MagicMock(status_code=429),
            body={"error": {"message": "Rate limit exceeded"}},
            message="Rate limit exceeded",
        )
        batch_processor.client.messages.batches = mock_batches

        result = batch_processor.process_batch(["T1110"], 0)
        assert isinstance(result, dict)
        assert len(result) == 0
        mock_sleep.assert_called_once_with(1)  # Verify sleep was called
    finally:
        # Restore original batches
        batch_processor.client.messages.batches = original_batches


@patch("time.sleep")
def test_batch_completion_rate_limit(mock_sleep: MagicMock, batch_processor: BatchProcessor) -> None:
    """Test handling rate limit errors during batch completion check."""
    # Create a mock that first raises RateLimitError, then returns "ended" status
    mock_batches = MagicMock()
    mock_status = MagicMock()
    mock_status.processing_status = "ended"
    mock_batches.retrieve.side_effect = [
        RateLimitError(
            response=MagicMock(status_code=429),
            body={"error": {"message": "Rate limit exceeded"}},
            message="Rate limit exceeded",
        ),
        mock_status,
    ]

    # Replace the client's batches with our mock
    original_batches = batch_processor.client.messages.batches
    try:
        batch_processor.client.messages.batches = mock_batches
        batch_processor._wait_for_batch_completion("test_batch_123")
        # Verify sleep was called once
        mock_sleep.assert_called_once_with(1)
        # Verify retrieve was called twice
        assert mock_batches.retrieve.call_count == 2
    finally:
        # Restore original batches
        batch_processor.client.messages.batches = original_batches


def test_process_batch_results_error(batch_processor: BatchProcessor) -> None:
    """Test handling errors in batch results."""
    # Replace the client's batches with a mock that returns error results
    original_batches = batch_processor.client.messages.batches
    try:

        class MockErrorResult:
            def __init__(self) -> None:
                self.custom_id = "technique_0"
                self.result = type("MockResultType", (), {"type": "errored", "error": "Test error message"})

        mock_batches = MagicMock()
        mock_batches.results.return_value = [MockErrorResult()]
        batch_processor.client.messages.batches = mock_batches

        results = batch_processor._process_batch_results("test_batch_123")
        assert isinstance(results, dict)
        assert len(results) == 0
    finally:
        # Restore original batches
        batch_processor.client.messages.batches = original_batches


def test_generate_threat_models_no_techniques(batch_processor: BatchProcessor, tmp_path: Path) -> None:
    """Test handling no techniques found."""
    # Create empty DataFrame with required columns
    batch_processor.data_processor.mitre_data = pd.DataFrame(columns=["TID", "Tactic", "Technique", "Description"])
    output_file = tmp_path / "empty_output.md"

    with pytest.raises(ValueError, match="No MITRE techniques found in data"):
        batch_processor.generate_threat_models(str(output_file))


def test_wait_for_batch_completion(batch_processor: BatchProcessor) -> None:
    """Test waiting for batch completion."""
    # Mock the batch status to be "ended" immediately
    batch_processor.client.messages.batches.processing_status = "ended"
    batch_processor._wait_for_batch_completion("test_batch_123")
    # If no exception is raised, the test passes


def test_process_batch_results(batch_processor: BatchProcessor) -> None:
    """Test processing batch results."""
    results = batch_processor._process_batch_results("test_batch_123")

    assert isinstance(results, dict)
    assert "technique_0" in results
    assert results["technique_0"].startswith("# Test Threat Model Content")


def test_save_results(batch_processor: BatchProcessor, tmp_path: Path) -> None:
    """Test saving results to file."""
    output_file = tmp_path / "test_output.md"
    content = {"technique_0": "# Test Content\nTest threat model content"}

    batch_processor._save_results(str(output_file), content)

    assert output_file.exists()
    with open(output_file) as f:
        saved_content = f.read()
        assert "# Microsoft 365 & Entra ID Threat Models" in saved_content
        assert "# Test Content" in saved_content


def test_create_introduction(batch_processor: BatchProcessor) -> None:
    """Test creation of introduction text."""
    intro = batch_processor._create_introduction()

    assert isinstance(intro, str)
    assert "# Microsoft 365 & Entra ID Threat Models" in intro
    assert "This document contains detailed threat models" in intro


def test_create_system_prompt(batch_processor: BatchProcessor) -> None:
    """Test creation of system prompt."""
    audit_ops = {"UserLoginFailed": {"FriendlyName": "Failed Login", "Description": "Test description"}}

    prompt = batch_processor._create_system_prompt(audit_ops)

    assert isinstance(prompt, str)
    assert "You are a cybersecurity expert" in prompt
    assert "MITRE Techniques" in prompt
    assert "Available Audit Operations" in prompt


def test_create_technique_prompt(batch_processor: BatchProcessor) -> None:
    """Test creation of technique prompt."""
    audit_ops = {"UserLoginFailed": {"FriendlyName": "Failed Login", "Description": "Test description"}}

    prompt = batch_processor._create_technique_prompt("T1110", audit_ops)

    assert isinstance(prompt, str)
    assert "Generate a detailed threat model" in prompt
    assert "T1110" in prompt
    assert "Detection strategies" in prompt
