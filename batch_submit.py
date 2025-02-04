import logging
import os
import time
import json
import pandas as pd
from random import choice
from typing import Dict, Any, List
import anthropic
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages.batch_create_params import Request

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

EXAMPLE_FORMAT = """
Threat Model: Office Application Startup (T1137) in Microsoft 365 & Entra ID

Overview
This threat model analyzes the various ways threat actors can abuse Microsoft Office application startup mechanisms for persistence, code execution, and defense evasion in Microsoft 365 and Entra ID environments. The model covers detection strategies using audit logs and provides example log entries for various attack scenarios.

Attack Vectors
1. Office Template Macros (T1137.001)
Description
Adversaries abuse Office templates to maintain persistence by adding malicious macros that execute when a new document is created.

Attack Scenarios
- Global template modification (Normal.dotm)
- Workgroup template deployment
- Network startup locations compromise

Detection Fields
{
  "Important Fields": {
    "Operation": ["FileModified", "FileAccessed"],
    "SourceFileName": ["*.dotm", "*.dotx", "*.xltx", "*.xltm"],
    "ClientIP": "string",
    "UserId": "string",
    "WorkloadName": "OneDrive",
    "ObjectId": "string",
    "TargetFilePath": "string"
  }
}

Example Audit Log
{
  "CreationTime": "2025-01-30T15:22:33",
  "Operation": "FileModified",
  "UserId": "user@contoso.com",
  "SourceFileName": "Normal.dotm",
  "TargetFilePath": "/personal/user_contoso_com/Documents/"
}

Detection Strategies
1. Behavioral Analytics
- Monitor for unusual template modifications outside business hours
- Track frequency of add-in installations across users
- Analyze patterns of macro execution across departments

2. Baseline Deviations
- Document normal template usage patterns
- Establish add-in whitelists
- Monitor for unauthorized registry modifications

Mitigation Strategies
Administrative Controls
- Implement strict add-in deployment policies
- Restrict template modification permissions
- Enable protected view for Office applications

Technical Controls
{
  "Office365Settings": {
    "MacroExecution": "DisableWithoutNotification",
    "ProtectedView": "EnabledForAllFiles",
    "AddInDeployment": "RestrictToApprovedList"
  }
}

Monitoring Controls
- Enable detailed Office 365 audit logging
- Implement real-time alerting for suspicious modifications
- Deploy endpoint detection and response (EDR) solutions
"""

THREAT_MODEL_PROMPT = f"""You are a highly skilled cyber security expert with deep understanding and knowledge of threat actors, Advanced Persistent Threats (APTs), security operations, threat hunting, Microsoft 365, and the MITRE ATT&CK framework. Your task is to generate a detailed threat model for Microsoft 365 and Entra ID, using the provided mappings and data to assist you.

First, review the provided data:

<MITRE_MAPPING>
{{MITRE_MAPPING}}
</MITRE_MAPPING>

<IDP_MAPPING>
{{IDP_MAPPING}}
</IDP_MAPPING>

<AUDIT_OPERATIONS>
{{AUDIT_OPERATIONS}}
</AUDIT_OPERATIONS>

Here is an example of the format to follow for your threat model:

<EXAMPLE_FORMAT>
{EXAMPLE_FORMAT}
</EXAMPLE_FORMAT>

Using this information and your expertise, generate a comprehensive threat model for Microsoft 365 and Entra ID. Follow the exact format shown in the example above, including:

1. Overview section describing the threat context
2. Attack Vectors section with subsections for each technique
3. Detection Fields in JSON format for each attack vector
4. Example Audit Logs in JSON format
5. Detection Strategies with specific examples
6. Mitigation Strategies including Administrative, Technical, and Monitoring controls
7. Technical Controls in JSON format where applicable

For each attack vector, ensure you include:
1. Description of the threat/attack
2. Specific attack scenarios
3. Detection fields in JSON format
4. Example audit log entries in JSON format
5. Relevant MITRE ATT&CK mappings
6. Applicable audit operations to monitor

<threat_model>
{{SECTION_DATA}}
</threat_model>

Format your response as a Markdown document following the exact structure of the example provided."""


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def create_client() -> anthropic.Anthropic:
    """Create and return an Anthropic client instance."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable is not set")
    return anthropic.Anthropic(api_key=api_key)


def generate_batch_id(prefix: str = "threat_model") -> str:
    """Generate a unique batch ID."""
    random_chars = ''.join(choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(8))
    return f"{prefix}_{random_chars}"


def parse_csv_file(file_path: str) -> pd.DataFrame:
    """Parse a CSV file into a pandas DataFrame with proper error handling."""
    try:
        if 'audit_operations' in file_path:
            # First attempt to detect the delimiter and structure
            with open(file_path, 'r', encoding='utf-8') as f:
                sample = f.read(4096)  # Read first 4KB to analyze

            # Try to determine if we have quoted fields with commas
            has_quotes = '"' in sample
            potential_delimiters = [',', '\t', '|']

            # Try different parsing configurations
            for delimiter in potential_delimiters:
                try:
                    df = pd.read_csv(
                        file_path,
                        delimiter=delimiter,
                        encoding='utf-8',
                        quotechar='"' if has_quotes else None,
                        escapechar='\\',
                        on_bad_lines='warn',
                        dtype={
                            'FriendlyName': str,
                            'Operation': str,
                            'Description': str
                        },
                        skipinitialspace=True
                    )

                    # Check if we got our expected columns
                    if all(col in df.columns for col in ['FriendlyName', 'Operation', 'Description']):
                        break
                except Exception as e:
                    logger.debug(f"Attempted delimiter '{delimiter}' failed: {str(e)}")
                    continue
            else:
                # If we get here, no delimiter worked
                raise ValueError("Could not determine correct delimiter for audit operations CSV")

            # Clean up the data
            # Handle any HTML or special characters in Description field
            df['Description'] = df['Description'].str.replace(r'<[^>]+>', '', regex=True)
            df['Description'] = df['Description'].str.replace(r'\s+', ' ', regex=True)

            # Remove rows where all required fields are empty
            df = df.dropna(subset=['FriendlyName', 'Operation'], how='all')

            # Remove duplicate operations, keeping the first occurrence
            df = df.drop_duplicates(subset=['Operation'], keep='first')

            # Fill any remaining NaN values with empty strings
            df = df.fillna('')

            # Trim whitespace from all fields
            for col in df.columns:
                if df[col].dtype == object:
                    df[col] = df[col].str.strip()

            logger.info(f"Successfully parsed {file_path} with {len(df)} rows")
            logger.debug(f"Unique operations found: {len(df['Operation'].unique())}")
            return df

        else:
            # For MITRE and IDP CSV files
            df = pd.read_csv(
                file_path,
                encoding='utf-8',
                on_bad_lines='warn'
            )

            # Basic validation for expected columns
            if 'TID' not in df.columns:
                raise ValueError(f"Required column 'TID' not found in {file_path}")

            logger.info(f"Successfully parsed {file_path}")
            return df

    except Exception as e:
        logger.error(f"Error parsing CSV file {file_path}: {str(e)}")
        # Log more details about the file
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                sample = f.read(1000)
            logger.error(f"First 1000 characters of problematic file:\n{sample}")
        except Exception as read_error:
            logger.error(f"Could not read sample from file: {str(read_error)}")
        raise


def convert_to_structured_data(df: pd.DataFrame, index_col: str) -> Dict[str, Dict[str, Any]]:
    """Convert DataFrame to structured dictionary with error handling."""
    try:
        # Convert DataFrame to dict after cleaning
        cleaned_df = df.copy()

        # Handle any data type conversions
        for col in cleaned_df.columns:
            if cleaned_df[col].dtype == object:
                cleaned_df[col] = cleaned_df[col].fillna('').astype(str)
            else:
                cleaned_df[col] = cleaned_df[col].fillna(0)

        # Remove any problematic characters from keys
        cleaned_df[index_col] = cleaned_df[index_col].str.strip()

        # Convert to dictionary
        result = {}
        for _, row in cleaned_df.iterrows():
            key = str(row[index_col])
            if key and key != 'nan':  # Skip empty or NaN keys
                result[key] = row.to_dict()

        return result
    except Exception as e:
        logger.error(f"Error converting DataFrame to structured data: {str(e)}")
        raise


def create_batch_request(mitre_data: Dict[str, Any],
                         idp_data: Dict[str, Any],
                         audit_ops: Dict[str, Any],
                         section_data: str,
                         custom_id: str) -> Request:
    """Create a single batch request with proper system messages."""

    # Convert audit_ops data to a more structured format
    formatted_audit_ops = {}
    for _, row in audit_ops.items():
        formatted_audit_ops[row.get('Operation', '')] = {
            'FriendlyName': row.get('FriendlyName', ''),
            'Description': row.get('Description', '')
        }

    system_content = [
        {
            "type": "text",
            "text": "You are a cybersecurity expert specialized in threat modeling for Microsoft 365 and Entra ID. "
                    "You will analyze threats and create detailed threat models following a specific format."
        },
        {
            "type": "text",
            "text": f"MITRE ATT&CK Data:\n{json.dumps(mitre_data, indent=2)}",
            "cache_control": {"type": "ephemeral"}
        },
        {
            "type": "text",
            "text": f"IDP Mapping Data:\n{json.dumps(idp_data, indent=2)}",
            "cache_control": {"type": "ephemeral"}
        },
        {
            "type": "text",
            "text": f"Audit Operations:\n{json.dumps(formatted_audit_ops, indent=2)}",
            "cache_control": {"type": "ephemeral"}
        }
    ]

    return Request(
        custom_id=custom_id,
        params=MessageCreateParamsNonStreaming(
            model="claude-3-5-sonnet-20241022",
            max_tokens=8192,
            system=system_content,
            messages=[{
                "role": "user",
                "content": f"Generate a threat model for the following section:\n{section_data}\n\n"
                           "Follow the exact format from the example, including all JSON structures for "
                           "detection fields and technical controls."
            }]
        )
    )


def submit_batch_requests(client: anthropic.Anthropic,
                          mitre_data: Dict[str, Any],
                          idp_data: Dict[str, Any],
                          audit_ops: Dict[str, Any],
                          sections: List[str]) -> Any:
    """Submit batch requests using the Anthropic Python library."""
    try:
        requests = [
            create_batch_request(
                mitre_data,
                idp_data,
                audit_ops,
                section,
                f"section_{i}"
            )
            for i, section in enumerate(sections)
        ]

        message_batch = client.messages.batches.create(requests=requests)
        logger.info(f"Batch submitted successfully. Batch ID: {message_batch.id}")
        return message_batch
    except Exception as e:
        logger.error(f"Error submitting batch request: {str(e)}")
        raise


def wait_for_batch_completion(client: anthropic.Anthropic, batch_id: str, interval: int = 60) -> None:
    """Wait for a batch request to complete processing."""
    while True:
        try:
            message_batch = client.messages.batches.retrieve(batch_id)
            if message_batch.processing_status == "ended":
                logger.info(f"Batch {batch_id} processing completed")
                break
            logger.info(f"Batch {batch_id} still processing. Waiting {interval} seconds.")
            time.sleep(interval)
        except Exception as e:
            logger.error(f"Error checking batch status: {str(e)}")
            time.sleep(interval)


def retrieve_and_process_results(client: anthropic.Anthropic, batch_id: str) -> Dict[str, str]:
    """Retrieve and process batch results."""
    try:
        content = {}
        for result in client.messages.batches.results(batch_id):
            if result.result.type == "succeeded":
                # Extract the text content from the message
                message_content = result.result.message.content
                section_text = []
                for content_item in message_content:
                    if content_item.type == "text":
                        section_text.append(content_item.text)
                content[result.custom_id] = "\n".join(section_text)
            else:
                logger.error(f"Request {result.custom_id} failed with type: {result.result.type}")
                if result.result.type == "errored":
                    logger.error(f"Error details: {result.result.error}")

        return content
    except Exception as e:
        logger.error(f"Error retrieving batch results: {str(e)}")
        raise


def save_threat_model(content: Dict[str, str], filename: str) -> None:
    """Save the generated threat model sections to a markdown file."""
    try:
        with open(filename, 'w') as f:
            # Sort sections by their number to maintain order
            sorted_sections = sorted(content.items(), key=lambda x: int(x[0].split('_')[1]))
            for _, section_content in sorted_sections:
                f.write(section_content + "\n\n")
        logger.info(f"Threat model saved to {filename}")
    except IOError as e:
        logger.error(f"Error saving threat model: {str(e)}")




def main(mitre_csv_path: str,
         idp_csv_path: str,
         audit_ops_path: str,
         section_data: List[str],
         output_file: str = "threat_model.md") -> None:
    """Main function to orchestrate threat model generation."""
    # Initialize client and parse all data sources
    client = create_client()

    # Parse all CSV files with validation
    logger.info("Starting CSV parsing...")
    mitre_df = parse_csv_file(mitre_csv_path)
    idp_df = parse_csv_file(idp_csv_path)
    audit_ops_df = parse_csv_file(audit_ops_path)

    # Convert to structured data with proper error handling
    logger.info("Converting parsed data to structured format...")
    mitre_data = convert_to_structured_data(mitre_df, 'TID')
    idp_data = convert_to_structured_data(idp_df, 'TID')
    audit_ops = convert_to_structured_data(audit_ops_df, 'FriendlyName')

    # Validate data before proceeding
    if not all([mitre_data, idp_data, audit_ops]):
        raise ValueError("One or more data sources is empty after processing")

    # Log data statistics
    logger.info(f"Processed {len(mitre_data)} MITRE entries")
    logger.info(f"Processed {len(idp_data)} IDP entries")
    logger.info(f"Processed {len(audit_ops)} audit operations")

    # Create and submit batch request
    message_batch = submit_batch_requests(client, mitre_data, idp_data, audit_ops, section_data)

    # Wait for completion and retrieve results
    wait_for_batch_completion(client, message_batch.id)
    model_content = retrieve_and_process_results(client, message_batch.id)

    # Save the results
    save_threat_model(model_content, output_file)
    logger.info("Threat model generation completed successfully")


if __name__ == "__main__":
    # Example usage
    mitre_csv_path = "office_suite_description_mitre_dump.csv"
    idp_csv_path = "idp_description_mitre_dump.csv"
    audit_ops_path = "audit_operations.csv"

    sections = [
        """Section 1: Authentication Mechanisms""",
        """Section 2: Data Access Controls""",
        """Section 3: Application Security"""
    ]

    main(mitre_csv_path, idp_csv_path, audit_ops_path, sections)