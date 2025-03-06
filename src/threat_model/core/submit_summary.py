#!/usr/bin/env python3
"""Script to process summary and submit to Claude API batch job."""
# Standard library imports
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, TypeVar, Protocol, Any

# Third-party imports
import anthropic
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages import MessageBatch, MessageBatchIndividualResponse
from anthropic.types.messages.batch_create_params import Request

from ruamel.yaml import YAML

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

T = TypeVar("T")


class BatchComponent(Protocol):
    """Base protocol for batch components with required attributes."""

    def process(self) -> None:
        """Process the batch component."""
        raise NotImplementedError

    def validate(self) -> bool:
        """Validate the batch component."""
        raise NotImplementedError


class MessageContent(BatchComponent):
    """Protocol for message content."""

    type: str
    text: Optional[str]

    def process(self) -> None:
        """Process the message content."""

    def validate(self) -> bool:
        """Validate message content properties."""
        return bool(self.type)


class BatchMessage(BatchComponent):
    """Protocol for batch message."""

    content: List[MessageContent]

    def process(self) -> None:
        """Process the batch message."""

    def validate(self) -> bool:
        """Validate batch message properties."""
        return bool(self.content)


class BatchResult(BatchComponent):
    """Protocol for batch result."""

    type: str
    message: BatchMessage
    error: Optional[str]

    def process(self) -> None:
        """Process the batch result."""

    def validate(self) -> bool:
        """Validate batch result properties."""
        return bool(self.type and self.message)


class BatchRequest(BatchComponent):
    """Protocol for batch request."""

    custom_id: str

    def process(self) -> None:
        """Process the batch request."""

    def validate(self) -> bool:
        """Validate batch request properties."""
        return bool(self.custom_id)


class BatchResponse(BatchComponent):
    """Protocol for batch response."""

    result: BatchResult
    request: BatchRequest

    def process(self) -> None:
        """Process the batch response."""

    def validate(self) -> bool:
        """Validate batch response properties."""
        return bool(self.result and self.request)


class BatchProcessingError(Exception):
    """Custom exception for batch processing errors."""


class BatchProcessor:  # pylint: disable=R0903
    """Class to handle batch processing operations."""

    def __init__(self, client: anthropic.Anthropic):
        """Initialize batch processor with Anthropic client."""
        self.client = client

    def create_batch_request(self, summary_data: Dict[str, Any], custom_id: str) -> Request:
        """Create a batch request for the summary data."""
        parsed_data = self._parse_xml_content(summary_data.get("content", ""))
        system_message = self._create_system_message(parsed_data)

        return Request(
            custom_id=custom_id,
            params=MessageCreateParamsNonStreaming(
                model="claude-3-5-sonnet-20241022",
                max_tokens=8192,
                system=system_message,
                messages=[
                    {"role": "user", "content": "Please analyze this environment and provide a detailed report."}
                ],
            ),
        )

    def _parse_xml_content(self, content: str) -> Dict[str, Any]:
        """Parse XML-style tokens from content."""
        result: Dict[str, Any] = {}

        # Extract task information
        task_content = self._extract_xml_section(content, "task")
        if task_content:
            result["task"] = task_content.strip()

        # Extract environment details
        env_content = self._extract_xml_section(content, "environment_details")
        if env_content:
            result["environment"] = self._parse_environment_sections(env_content)

        return result

    def _extract_xml_section(self, content: str, tag: str) -> Optional[str]:
        """Extract content between XML-style tags."""
        start_tag = f"<{tag}>"
        end_tag = f"</{tag}>"
        start_pos = content.find(start_tag)
        end_pos = content.find(end_tag)

        if start_pos >= 0 and end_pos >= 0:
            return content[start_pos + len(start_tag) : end_pos]
        return None

    def _parse_environment_sections(self, env_content: str) -> Dict[str, str]:
        """Parse environment content into sections."""
        sections: Dict[str, List[str]] = {}
        current_section = ""

        for line in env_content.strip().split("\n"):
            line = line.strip()
            if line.startswith("# "):
                current_section = line[2:]
                sections[current_section] = []
            elif line and current_section:
                sections[current_section].append(line)

        return {key: "\n".join(values) for key, values in sections.items()}

    def _create_system_message(self, parsed_data: Dict[str, Any]) -> str:
        """Create system message from parsed data."""
        return f"""You are analyzing the following task and environment:
<task>
{parsed_data.get('task', '')}
</task>
<environment_details>:
{json.dumps(parsed_data.get('environment', {}), indent=2)}
</environment_details>
Please provide a detailed technical report based on this context."""


def create_client() -> anthropic.Anthropic:
    """Create and return an Anthropic client instance."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable is not set")
    return anthropic.Anthropic(api_key=api_key)


def process_files(file_paths: List[Path], processor: Any, client: anthropic.Anthropic, output_dir: str) -> None:
    """Process multiple files in a batch."""
    batch_handler = BatchFileProcessor(processor, client, output_dir)
    batch_handler.process_files(file_paths)


def process_directory(
    dir_path: Path, recursive: bool, processor: Any, client: anthropic.Anthropic, output_dir: str
) -> None:
    """Process all valid files in a directory."""
    batch_handler = BatchDirectoryProcessor(processor, client, output_dir)
    batch_handler.process_directory(dir_path, recursive)


class BatchFileProcessor:  # pylint: disable=R0903
    """Handler for batch file processing."""

    def __init__(self, processor: Any, client: anthropic.Anthropic, output_dir: str):
        """Initialize the batch file processor."""
        self.processor = processor
        self.client = client
        self.output_dir = output_dir
        self.batch_processor = BatchProcessor(client)
        os.makedirs(output_dir, exist_ok=True)

    def process_files(self, file_paths: List[Path]) -> None:
        """Process multiple files in a batch."""
        requests = []
        summaries: Dict[str, Dict[str, Any]] = {}

        for file_path in file_paths:
            request, summary = self._prepare_file_request(file_path)
            if request:
                requests.append(request)
                summaries[request.get("custom_id")] = summary
        if requests:
            self._process_batch_requests(requests, summaries)

    def _prepare_file_request(self, file_path: Path) -> tuple[Optional[Request], Dict[str, Any]]:
        """Prepare a batch request for a file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            summary = self.processor.generate_summary(content)
            custom_id = f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

            request = self.batch_processor.create_batch_request(summary, custom_id)

            return request, {"summary": summary, "file_path": file_path}
        except FileNotFoundError:
            logger.error("File not found: %s", file_path)
            raise
        except PermissionError:
            logger.error("Permission denied: %s", file_path)
            raise

    def _process_batch_requests(self, requests: List[Request], summaries: Dict[str, Dict[str, Any]]) -> None:
        """Process a batch of requests."""
        try:
            message_batch = self.client.messages.batches.create(requests=requests)
            if not isinstance(message_batch, MessageBatch):
                raise BatchProcessingError("Invalid message batch response type")

            batch_id = str(message_batch.id)
            self._wait_for_batch_completion(batch_id)
            self._process_batch_results(batch_id, summaries)

        except Exception as e:
            logger.error("Error processing batch requests: %s", str(e))
            raise

    def _wait_for_batch_completion(self, batch_id: str, interval: int = 60) -> None:
        """Wait for batch processing to complete."""
        while True:
            batch_status = self.client.messages.batches.retrieve(batch_id)
            if batch_status.processing_status == "ended":
                logger.info("Batch %s completed successfully", batch_id)
                break
            logger.info("Batch %s still processing. Waiting %d seconds...", batch_id, interval)
            time.sleep(interval)

    def _process_batch_results(self, batch_id: str, summaries: Dict[str, Dict[str, Any]]) -> None:
        """Process results from a completed batch."""
        yaml_handler = YAML()
        yaml_handler.indent(mapping=2, sequence=4, offset=2)

        for result in self.client.messages.batches.results(batch_id):
            response = self._validate_batch_response(result)
            if not response:
                continue

            custom_id = response.custom_id
            file_info = summaries.get(custom_id)

            if not file_info:
                logger.error("No file info found for custom_id: %s", custom_id)
                continue

            if response.result.type == "succeeded":
                self._save_successful_result(response, file_info, yaml_handler)
            else:
                logger.error("Failed to process request %s: %s", custom_id, response.result.error or "Unknown error")

    def _validate_batch_response(self, result: Any) -> Optional[MessageBatchIndividualResponse]:
        """Validate and cast batch response."""
        try:
            response = result
            if not isinstance(response, MessageBatchIndividualResponse):
                logger.error("Invalid response format")
                return None
            return response
        except ValueError:
            logger.error("Invalid response format")
            return None
        except AttributeError:
            logger.error("Invalid response format")
            return None

    def _save_successful_result(
        self, response: MessageBatchIndividualResponse, file_info: Dict[str, Any], yaml_handler: YAML
    ) -> None:
        """Save successful batch result."""
        try:
            content_parts = []
            for content_item in response.result.message.content:
                if content_item.type == "text" and content_item.text:
                    content_parts.append(content_item.text)

            response_text = "\n\n".join(content_parts) if content_parts else "No content available"

            # Generate unique filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            conv_id = file_info["summary"].get("conversation_id", uuid.uuid4().hex[:8])
            output_file = os.path.join(self.output_dir, f"summary_{timestamp}_{conv_id}.yaml")

            # Add batch response to summary
            file_info["summary"]["batch_response"] = {
                "timestamp": datetime.now().isoformat(),
                "model": "claude-3-5-sonnet-20241022",
                "max_tokens": 8192,
                "content": response_text,
            }

            # Save YAML file
            with open(output_file, "w", encoding="utf-8") as f:
                yaml_handler.dump(file_info["summary"], f)

            logger.info("Successfully processed file: %s", file_info["file_path"])

        except FileNotFoundError:
            logger.error("File not found: %s", file_info["file_path"])
            raise
        except PermissionError:
            logger.error("Permission denied: %s", file_info["file_path"])
            raise


class BatchDirectoryProcessor:  # pylint: disable=R0903
    """Handler for batch directory processing."""

    def __init__(self, processor: Any, client: anthropic.Anthropic, output_dir: str):
        """Initialize the batch directory processor."""
        self.processor = processor
        self.client = client
        self.output_dir = output_dir
        self.file_processor = BatchFileProcessor(processor, client, output_dir)

    def process_directory(self, dir_path: Path, recursive: bool) -> None:
        """Process all valid files in a directory."""
        valid_extensions = {".md", ".txt"}

        try:
            files = self._get_valid_files(dir_path, recursive, valid_extensions)
            if not files:
                logger.warning("No valid files found in directory: %s", dir_path)
                return

            logger.info("Found %d valid files in directory: %s", len(files), dir_path)

            # Process files in batches of 1000
            batch_size = 1000
            for i in range(0, len(files), batch_size):
                batch = files[i : i + batch_size]
                self.file_processor.process_files(batch)
                logger.info("Processed batch %d", i // batch_size + 1)

        except FileNotFoundError:
            logger.error("Directory not found: %s", dir_path)
            raise
        except PermissionError:
            logger.error("Permission denied: %s", dir_path)
            raise

    def _get_valid_files(self, dir_path: Path, recursive: bool, valid_extensions: set[str]) -> List[Path]:
        """Get all valid files from directory.

        Args:
            dir_path: Directory path to search
            recursive: Whether to search recursively
            valid_extensions: Set of valid file extensions

        Returns:
            List of valid file paths
        """
        if recursive:
            files = [p for p in dir_path.rglob("*") if p.is_file() and p.suffix in valid_extensions]
        else:
            files = [p for p in dir_path.iterdir() if p.is_file() and p.suffix in valid_extensions]
        return files
