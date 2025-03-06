#!/usr/bin/env python3 # noqa: E265
"""
Summary Processor Module

This module provides functionality for processing batch inputs and generating YAML summaries
with schema validation. It includes components for context analysis, YAML generation,
and schema validation.
"""
from io import StringIO
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging
import uuid

from ruamel.yaml import YAML
import pydantic
from pydantic import BaseModel, Field

try:
    from jsonschema import validate as json_validate
    from jsonschema.exceptions import ValidationError as JsonValidationError

    SCHEMA_VALIDATION_AVAILABLE = True
except ImportError:
    SCHEMA_VALIDATION_AVAILABLE = False
    json_validate = None
    JsonValidationError = Exception

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class SummaryConfig:
    """Configuration for summary processing."""

    output_max_length: int = 8192  # Max length for generated output
    input_max_tokens: int = 128000  # Default token limit for input
    batch_size: int = 10
    output_format: str = "yaml"
    schema_validation: bool = True


class SchemaValidationError(Exception):
    """Custom exception for schema validation errors."""


class ConversationMetadata(BaseModel):
    """Metadata model for conversations."""

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = Field(default="batch_processor")
    version: str = Field(default="1.0")
    tags: List[str] = Field(default_factory=list)


class Message(BaseModel):
    """Model for individual messages in a conversation."""

    role: str
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict = Field(default_factory=dict)


class Conversation(BaseModel):
    """Model for complete conversations."""

    conversation_id: str = Field(default_factory=lambda: f"conv_{uuid.uuid4().hex[:8]}")
    metadata: ConversationMetadata
    system: Optional[str] = None
    messages: List[Message]
    chosen: Optional[Dict] = None
    rejected: Optional[Dict] = None
    feedback: Optional[Dict] = None
    validation: Optional[Dict] = None


class ContextAnalyzer:
    """Analyzes input context and extracts key information."""

    def analyze_content(self, content: str) -> Dict:
        """
        Analyze the content and extract key information.

        Args:
            content: The input content to analyze

        Returns:
            Dict containing analyzed information
        """
        # Extract task and environment details
        task_start = content.find("<task>")
        task_end = content.find("</task>")
        env_start = content.find("<environment_details>")
        env_end = content.find("</environment_details>")

        task = content[task_start + 6 : task_end].strip() if task_start >= 0 and task_end >= 0 else ""
        env = content[env_start + 20 : env_end].strip() if env_start >= 0 and env_end >= 0 else ""

        # Parse environment details
        env_sections: Dict[str, List[str]] = {}
        current_section = ""
        for line in env.split("\n"):
            line = line.strip()
            if line.startswith("# "):
                current_section = line[2:]
                env_sections[current_section] = []
            elif line and current_section:
                env_sections[current_section].append(line)

        return {
            "length": len(content),
            "timestamp": datetime.utcnow().isoformat(),
            "type": "batch_input",
            "task": task,
            "environment": {k: "\n".join(v) for k, v in env_sections.items() if v},
        }

    def extract_key_points(self, content: str) -> List[str]:
        """
        Extract key points from the content.

        Args:
            content: The input content to analyze

        Returns:
            List of extracted key points
        """
        key_points = []
        # Extract task
        task_start = content.find("<task>")
        task_end = content.find("</task>")
        if task_start >= 0 and task_end >= 0:
            task = content[task_start + 6 : task_end].strip()
            key_points.append(f"Task: {task}")
        # Extract environment details
        env_start = content.find("<environment_details>")
        env_end = content.find("</environment_details>")
        if env_start >= 0 and env_end >= 0:
            env = content[env_start + 20 : env_end].strip()
            # Parse key sections
            for line in env.split("\n"):
                line = line.strip()
                if line.startswith("# "):
                    section = line[2:]
                    key_points.append(f"Environment: {section}")

        return key_points


class YAMLGenerator:
    """Generates YAML output following the schema."""

    def __init__(self) -> None:
        """Initialize the YAML generator."""
        self.yaml = YAML()
        self.yaml.indent(mapping=2, sequence=4, offset=2)

    def generate_yaml(self, data: Dict[str, Any]) -> str:
        """
        Generate YAML string from input data.

        Args:
            data: Dictionary of data to convert to YAML

        Returns:
            str: YAML formatted string
        """
        # Create conversation model
        conversation = Conversation(
            metadata=ConversationMetadata(**data.get("metadata", {})),
            messages=[Message(**msg) for msg in data.get("messages", [])],
            system=data.get("system"),
            chosen=data.get("chosen"),
            rejected=data.get("rejected"),
            feedback=data.get("feedback"),
            validation=data.get("validation"),
        )
        # Convert to dict and then YAML
        stream = StringIO()
        self.yaml.dump(conversation.model_dump(), stream)
        return stream.getvalue()

    def validate_schema(self, data: Dict) -> bool:
        """
        Validate data against the schema.

        Args:
            data: Dictionary of data to validate

        Returns:
            True if valid, raises ValidationError if not
        """
        try:
            # Validate using pydantic model
            Conversation(**data)
            return True
        except pydantic.ValidationError as e:
            raise SchemaValidationError(f"Schema validation failed: {str(e)}") from e


class SchemaValidator:
    """Handles schema validation for YAML output."""

    def __init__(self, schema: Dict):
        """
        Initialize the schema validator.

        Args:
            schema: Dictionary containing the JSON schema
        """
        self.schema = schema

    def validate(self, data: Dict[str, Any]) -> bool:
        """
        Validate data against the schema.

        Args:
            data: Dictionary of data to validate

        Returns:
            True if valid, raises ValidationError if not
        """
        try:
            if SCHEMA_VALIDATION_AVAILABLE and json_validate:
                json_validate(instance=data, schema=self.schema)
                return True
            logger.warning("JSON Schema validation not available - skipping validation")
            return True
        except JsonValidationError as e:
            raise SchemaValidationError(f"Schema validation failed: {str(e)}") from e

    def error_handling(self, errors: List[str]) -> None:
        """
        Handle validation errors.

        Args:
            errors: List of error messages
        """
        for error in errors:
            logger.error("Validation error: %s", error)


class SummaryProcessor:
    """Main class for processing summaries and generating YAML output."""

    def __init__(self, config: SummaryConfig):
        """
        Initialize the summary processor.

        Args:
            config: Configuration object for the processor
        """
        self.config = config
        self.analyzer = ContextAnalyzer()
        self.generator = YAMLGenerator()
        self.validator = SchemaValidator(Conversation.model_json_schema())
        logger.info("Initialized SummaryProcessor with config: %s", config)

    def process_batch(self, inputs: List[str]) -> None:
        """
        Process a batch of inputs.

        Args:
            inputs: List of input strings to process
        """
        for i, input_text in enumerate(inputs):
            try:
                result = self.generate_summary(input_text)
                logger.info("Processed input %d/%d", i + 1, len(inputs))
                if self.config.output_format == "yaml":
                    output_path = f"output/summary_{i + 1}.yaml"
                    self.create_yaml(result, output_path)
                else:
                    logger.warning("Unsupported output format: %s", self.config.output_format)
            except SchemaValidationError as sve:
                logger.error("Schema validation error processing input %d: %s", i + 1, str(sve))

    def generate_summary(self, context: str) -> Dict[str, Any]:
        """
        Generate a summary from input context.

        Args:
            context: Input context to summarize

        Returns:
            Dictionary containing the generated summary
        """
        # Analyze content
        analysis = self.analyzer.analyze_content(context)
        key_points = self.analyzer.extract_key_points(context)

        # Create summary data
        summary_data = {
            "key_points": key_points,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "batch_processor",
                "version": "1.0",
                "tags": ["summary", "batch"],
            },
            "messages": [
                {
                    "role": "system",
                    "content": "Processing batch input for summary generation",
                    "timestamp": datetime.utcnow().isoformat(),
                },
                {
                    "role": "user",
                    "content": context,  # Store complete input
                    "timestamp": datetime.utcnow().isoformat(),
                    "metadata": analysis,
                },
            ],
            "validation": {
                "required_fields": ["conversation_id", "messages"],
                "input_max_tokens": self.config.input_max_tokens,
                "output_max_length": self.config.output_max_length,
            },
        }
        # Validate and generate YAML
        if self.config.schema_validation:
            self.validator.validate(summary_data)

        return summary_data

    def create_yaml(self, data: Dict, path: str) -> None:
        """
        Create YAML file from summary data.

        Args:
            data: Dictionary of summary data
            path: Output file path
        """
        try:
            yaml_content = self.generator.generate_yaml(data)
            with open(path, "w", encoding="utf-8") as f:
                f.write(yaml_content)
            logger.info("Created YAML file: %s", path)
        except Exception as e:
            logger.error("Error creating YAML file: %s", str(e))
            raise
