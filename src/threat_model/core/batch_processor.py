"""Batch processing module for threat model generation."""

import json

# Standard library imports
import logging
import time
from typing import Dict, List, Any

# Third-party imports
from anthropic import RateLimitError, Anthropic
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages.batch_create_params import Request

# Local imports
from .config import (
    DEFAULT_MODEL,
    MAX_TOKENS,
    BATCH_SIZE,
)

logger = logging.getLogger(__name__)

# Sleep time for rate limit retries (in seconds)
SLEEP_TIME = 1  # Reduced for testing


class BatchProcessor:
    """Handles batch processing of threat model generation requests."""

    def __init__(self, client: Anthropic, data_processor: Any):
        """Initialize the batch processor.

        Args:
            client: Initialized Anthropic client
            data_processor: DataProcessor instance for accessing MITRE data
        """
        self.client = client
        self.data_processor = data_processor

    def _create_batch_request(self, technique_id: str, custom_id: str) -> Dict[str, Any]:
        """Create a single batch request with proper system messages.

        Args:
            technique_id: MITRE technique ID
            custom_id: Unique identifier for this request

        Returns:
            Dict: Configured batch request
        """
        # Convert audit ops data to a more structured format
        formatted_audit_ops = {}
        for _, row in self.data_processor.audit_data.iterrows():
            formatted_audit_ops[row.get("Operation", "")] = {
                "FriendlyName": row.get("FriendlyName", ""),
                "Description": row.get("Description", ""),
            }
        # Create system prompt
        system_prompt = self._create_system_prompt(formatted_audit_ops)
        return {
            "custom_id": custom_id,
            "params": {
                "model": DEFAULT_MODEL,
                "max_tokens": MAX_TOKENS,
                "system": system_prompt,
                "messages": [
                    {"role": "user", "content": self._create_technique_prompt(technique_id, formatted_audit_ops)}
                ],
            },
        }

    def process_batch(self, technique_ids: List[str], batch_start: int) -> Dict[str, str]:
        """Process a single batch of technique IDs.

        Args:
            technique_ids: List of technique IDs to process
            batch_start: Starting index for this batch

        Returns:
            Dict[str, str]: Dictionary mapping technique IDs to generated content
        """
        requests: List[Dict[str, Any]] = []
        batch_content: Dict[str, str] = {}
        # Create batch requests
        for i, technique_id in enumerate(technique_ids):
            try:
                request = self._create_batch_request(technique_id, f"technique_{batch_start + i}")
                requests.append(request)
                logger.info("Request created for technique %s", technique_id)
            except ValueError as ve:
                logger.error("Value error for technique %s: %s", technique_id, str(ve))
                continue
            except KeyError as ke:
                logger.error("Key error for technique %s: %s", technique_id, str(ke))
                continue
            except Exception as e:  # disable=W0718 disable=bare-except
                logger.error("Unexpected error for technique %s: %s", technique_id, str(e))
                continue
        # Check if there are requests to process
        if not requests:
            return batch_content
        # Process requests in batches
        try:
            # Convert to Request objects
            request_objects = [
                Request(
                    custom_id=req["custom_id"],
                    params=MessageCreateParamsNonStreaming(
                        model=req["params"]["model"],
                        max_tokens=req["params"]["max_tokens"],
                        messages=req["params"]["messages"],
                        system=req["params"]["system"],
                    ),
                )
                for req in requests
            ]
            # Submit batch
            message_batch = self.client.messages.batches.create(requests=request_objects)
            logger.info("Batch submitted successfully. Batch ID: %s", message_batch.id)
            # Wait for completion
            self._wait_for_batch_completion(message_batch.id)
            # Process results
            batch_content = self._process_batch_results(message_batch.id)
        # Handle rate limits and other exceptions
        except RateLimitError as e:
            logger.error("Rate limit exceeded. Retrying in %d seconds. %s", SLEEP_TIME, str(e))
            time.sleep(SLEEP_TIME)
        except Exception as e:  # disable=W0718
            logger.error("Error processing batch: %s", str(e))
        # Handle empty batch
        return batch_content

    def generate_threat_models(self, output_file: str) -> None:
        """Generate threat models for all techniques in batches.

        Args:
            output_file: Path to output file
        """
        try:
            # Get technique IDs
            technique_ids = self.data_processor.mitre_data["TID"].unique().tolist()
            if not technique_ids:
                raise ValueError("No MITRE techniques found in data")
            logger.info("Found %s unique technique IDs", len(technique_ids))
            # Process in batches
            all_content = {}
            total_techniques = len(technique_ids)
            processed_techniques = 0
            # Process techniques in batches
            while processed_techniques < total_techniques:
                batch_start = processed_techniques
                batch_end = min(batch_start + BATCH_SIZE, total_techniques)
                current_batch = technique_ids[batch_start:batch_end]
                logger.info(
                    "Processing batch %s of %s", batch_start // BATCH_SIZE + 1, (total_techniques - 1) // BATCH_SIZE + 1
                )
                logger.info("Techniques in batch: %s", current_batch)
                batch_content = self.process_batch(current_batch, batch_start)
                all_content.update(batch_content)
                processed_techniques = batch_end
                logger.info("Completed %s of %s techniques in this batch", processed_techniques, total_techniques)
            # Save results
            self._save_results(output_file, all_content)
        except Exception as e:
            logger.error("Error generating threat models for techniques in batch: %s", str(e))
            raise

    def _wait_for_batch_completion(self, batch_id: str) -> None:
        """Wait for a batch to complete processing.

        Args:
            batch_id: ID of the batch to monitor
        """
        while True:
            try:
                batch_status = self.client.messages.batches.retrieve(batch_id)
                if batch_status.processing_status == "ended":
                    logger.info("Batch %s processing completed", batch_id)
                    break
                logger.info("Batch %s still processing. Status: %s", batch_id, batch_status.processing_status)
                time.sleep(SLEEP_TIME)
            except RateLimitError as e:
                logger.error(
                    "Rate limit exceeded while checking batch status. Retrying in %d seconds. %s", SLEEP_TIME, str(e)
                )
                time.sleep(SLEEP_TIME)
            except Exception as e:  # disable=W0718 disable=bare-except
                logger.error("Error checking batch status: %s", str(e))
                time.sleep(SLEEP_TIME)

    def _process_batch_results(self, batch_id: str) -> Dict[str, str]:
        """Process results from a completed batch.

        Args:
            batch_id: ID of the completed batch

        Returns:
            Dict[str, str]: Dictionary mapping technique IDs to generated content
        """
        batch_content = {}
        for result in self.client.messages.batches.results(batch_id):
            if result.result.type == "succeeded":
                message_content = result.result.message.content
                section_text = []
                for content_item in message_content:
                    if content_item.type == "text":
                        section_text.append(content_item.text)
                batch_content[result.custom_id] = "\n".join(section_text)
            else:
                logger.error("Result for %s failed with type: %s", result.custom_id, result.result.type)
                if result.result.type == "errored":
                    logger.error("Error message: %s", result.result.error)
        return batch_content

    def _save_results(self, output_file: str, all_content: Dict[str, str]) -> None:
        """Save generated content to output file.

        Args:
            output_file: Path to output file
            all_content: Dictionary of generated content
        """
        with open(output_file, "w") as f:
            # Write introduction
            f.write(self._create_introduction())
            # Write table of contents
            sorted_techniques = sorted(all_content.items(), key=lambda x: int(x[0].split("_")[1]))
            f.write("## Table of Contents\n\n")
            for technique_id, content in sorted_techniques:
                # Extract title from content
                title = next((line for line in content.split("\n") if line.startswith("# Threat Model:")), "")
                if title:
                    title = title.replace("# Threat Model: ", "")
                    anchor = title.lower().replace(" ", "-").replace("(", "").replace(")", "").replace(".", "")
                    f.write(f"- [{title}](#{anchor})\n")
            f.write("\n---\n\n")
            # Write technique content
            for _, technique_content in sorted_techniques:
                f.write(f"{technique_content}\n\n")
                f.write("---\n\n")
        logger.info("Threat model saved to %s", output_file)
        logger.info("Generated %s technique-specific threat models", len(all_content))
        logger.info("Added table of contents with navigation links")

    @staticmethod
    def _create_introduction() -> str:
        """Create introduction text for the threat model document.

        Returns:
            str: Formatted introduction text
        """
        return (
            "# Microsoft 365 & Entra ID Threat Models\n\n"
            "This document contains detailed threat models for specific MITRE ATT&CK techniques "
            "relevant to Microsoft 365 and Entra ID environments.\n\n"
            "Each model includes:\n"
            "- Detailed attack vectors with example audit logs\n"
            "- SQL-based detection strategies\n"
            "- JSON-formatted technical controls\n"
            "- Specific incident response playbooks\n"
            "- Relevant references and documentation\n\n"
        )

    def _create_system_prompt(self, formatted_audit_ops: Dict[str, Any]) -> str:
        """Create system prompt for the model.

        Args:
            formatted_audit_ops: Dictionary of formatted audit operations

        Returns:
            str: System prompt for the model
        """
        return (
            "You are a cybersecurity expert specialized in threat modeling for Microsoft 365 and Entra ID.\n"
            "Your task is to create detailed threat models that:\n"
            "1. Map MITRE ATT&CK techniques to specific Microsoft 365 and Entra ID attack vectors\n"
            "2. Provide concrete detection strategies using actual audit operations\n"
            "3. Include example audit logs showing what malicious activity looks like\n"
            "4. Define behavioral analytics and baseline deviation monitoring\n"
            "5. Specify technical, administrative, and monitoring controls\n\n"
            "For each technique:\n"
            "- Use the MITRE data to understand the attack methodology\n"
            "- Map relevant audit operations that could detect this activity\n"
            "- Create example logs showing suspicious patterns\n"
            "- Define specific detection rules and thresholds\n"
            "- Provide actionable mitigation strategies\n\n"
            "Reference Data for Correlation:\n"
            f"MITRE Techniques:\n{json.dumps(self.data_processor.mitre_data.to_dict(), indent=2)}\n\n"
            f"IDP Mappings:\n{json.dumps(self.data_processor.idp_data.to_dict(), indent=2)}\n\n"
            f"Available Audit Operations:\n{json.dumps(formatted_audit_ops, indent=2)}\n\n"
            "Key Requirements:\n"
            "1. Every attack vector must include specific audit operations for detection\n"
            "2. Example logs must show realistic field names and values\n"
            "3. Detection strategies must include concrete thresholds and time windows\n"
            "4. Controls must be specific to Microsoft 365 and Entra ID capabilities"
        )

    def _create_technique_prompt(self, technique_id: str, audit_ops: dict) -> str:
        """Create a detailed prompt for a specific MITRE technique.

        Args:
            technique_id: The MITRE technique ID
            audit_ops: Dictionary of audit operations

        Returns:
            str: Formatted prompt string
        """
        # Get technique data
        technique_df = self.data_processor.mitre_data[self.data_processor.mitre_data["TID"] == technique_id]
        # Check if technique exists
        if technique_df.empty:
            raise ValueError(f"No technique found with ID: {technique_id}")
        # Extract technique data
        technique_data = technique_df.iloc[0]
        # Find relevant audit operations
        relevant_ops = [
            op
            for op, details in audit_ops.items()
            if any(term in details["Description"].lower() for term in technique_data["Description"].lower().split())
        ]
        return f"""Generate a detailed threat model for technique
    {technique_id} ({technique_data['Technique']}) following this exact structure:
    
    # Threat Model: {technique_data['Technique']} ({technique_id}) in Microsoft 365 & Entra ID
    
    Provide a comprehensive threat model that includes:
    
    1. Overview of the technique in Microsoft 365/Entra ID context
    2. At least 3 specific attack vectors with:
       - Detailed description
       - Real-world attack scenarios
       - Specific detection fields from audit logs
       - Example audit log entries showing indicators
    3. Detection strategies including:
       - Behavioral analytics rules
       - Baseline deviation monitoring
       - SQL correlation rules
    4. Mitigation strategies with:
       - Administrative controls
       - Technical controls (JSON format)
       - Monitoring controls
    5. Incident response playbook with:
       - Initial detection steps
       - Investigation procedures
       - Containment actions
    6. References to MITRE and Microsoft documentation
    
    Technique Description: {technique_data['Description']}
    Relevant Audit Operations: {json.dumps(relevant_ops, indent=2)}
    
    Use this information to create specific, actionable guidance.
    Focus on Microsoft 365 and Entra ID specific implementations and detections.
    Include realistic audit log examples that show actual field names and values.
    Provide concrete detection rules with specific thresholds and conditions."""
