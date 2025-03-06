"""Command line interface for threat model generator."""

import os
import sys
import argparse
from pathlib import Path
import logging
from typing import Any

import dotenv
from dotenv import load_dotenv

from threat_model.core.submit_summary import create_client, process_files, process_directory
from threat_model.core import ThreatModelGenerator
from threat_model.core.summary_processor import SummaryConfig, SummaryProcessor

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments.

    Returns:
        argparse.Namespace: Parsed command-line arguments
    """
    parser = argparse.ArgumentParser(description="A CLI for generating threat models and summaries using LLM")
    parser.add_argument("--mode", "-m", type=str, help="Mode to run the CLI in", default="threat_model")
    parser.add_argument(
        "--mitre-path", type=str, help="Path to MITRE CSV file", default="office_suite_description_mitre_dump.csv"
    )
    parser.add_argument("--idp-path", type=str, help="Path to IDP CSV file", default="idp_description_mitre_dump.csv")
    parser.add_argument(
        "--audit-path", type=str, help="Path to audit operations CSV file", default="audit_operations.csv"
    )
    parser.add_argument("--output", "-o", type=str, help="Output file path or directory", default="threat_model.md")
    parser.add_argument("--batch", action="store_true", help="Use batch processing mode")
    parser.add_argument("--recursive", "-r", action="store_true", help="Recursively process directories")
    parser.add_argument("--input", "-i", type=str, help="Input file or directory", default="summary_docs")
    parser.add_argument(
        "--sections",
        nargs="+",
        help="Section names for batch processing",
        default=["Authentication Mechanisms", "Data Access Controls", "Application Security"],
    )
    return parser.parse_args()


def get_api_key() -> str:
    """Retrieve the Anthropic API key from environment variables.

    Returns:
        str: The API key

    Raises:
        ValueError: If the API key is not set
    """
    api_key = os.getenv("ANTHROPIC_API_KEY") or dotenv.get_key(".env", "ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable not set")
    return api_key


def run_threat_model(args: argparse.Namespace, api_key: str) -> None:
    """Run the threat model generation process.

    Args:
        args: Command line arguments
        api_key: Anthropic API key
    """
    # Initialize generator
    generator = ThreatModelGenerator(api_key=api_key)

    # Convert paths to Path objects
    current_dir = Path(__file__).parent.parent.parent
    mitre_path = current_dir / args.mitre_path
    idp_path = current_dir / args.idp_path
    audit_path = current_dir / args.audit_path
    output_path = current_dir / args.output

    # Load data
    generator.load_data(mitre_path=mitre_path, idp_path=idp_path, audit_path=audit_path)

    # Generate threat model
    if args.batch:
        # Format sections for batch processing
        sections = [f"Section {i+1}: {section}" for i, section in enumerate(args.sections)]
        generator.generate_threat_model_batch(sections, output_path)
        logger.info("Batch threat model generation completed successfully")
    else:
        generator.generate_threat_model()
        logger.info("Threat model generation completed successfully")


def run_summary(args: argparse.Namespace) -> None:
    """Run the summary processing mode.

    Args:
        args: Command line arguments
    """
    # Configure the processor
    config = SummaryConfig(
        output_max_length=8192,
        input_max_tokens=128000,
        batch_size=1000,
        output_format="yaml",
        schema_validation=True,
    )

    processor = SummaryProcessor(config)
    client = create_client()

    # Convert input path to Path object
    input_path = Path(args.input)
    output_path = args.output

    # Create output directory if it doesn't exist
    os.makedirs(output_path, exist_ok=True)

    process_input(input_path, args.recursive, processor, client, output_path)


def process_input(
    input_path: Path, recursive: bool, processor: SummaryProcessor, client: Any, output_path: str
) -> None:
    """Process the input file or directory.

    Args:
        input_path: Path to the input file or directory
        recursive: Whether to recursively process directories
        processor: Summary processor instance
        client: API client
        output_path: Output directory path

    Raises:
        FileNotFoundError: If the input path doesn't exist
        ValueError: If there's an issue processing the input
    """
    if input_path.is_file():
        # Process single file
        process_files([input_path], processor, client, output_path)
    elif input_path.is_dir():
        # Process directory
        process_directory(input_path, recursive, processor, client, output_path)
    elif input_path.exists():
        # This branch handles any other file type that exists but isn't a regular file or directory
        logger.warning("Path exists but is not a regular file or directory: %s", input_path)
        raise ValueError(f"Unsupported file type: {input_path}")
    else:
        logger.error("Invalid input path: %s", input_path)
        raise FileNotFoundError(f"Input path not found: {input_path}")


def main() -> None:
    """Main entry point for the threat model CLI tool.

    This function orchestrates the entire process by:
    1. Parsing command line arguments
    2. Loading environment variables
    3. Retrieving API key
    4. Running the appropriate mode (threat_model or summary)
    5. Handling exceptions with appropriate error messages
    """
    try:
        # Parse command line arguments
        args = parse_args()

        # Load environment variables
        load_dotenv()

        # Get API key
        api_key = get_api_key()

        # Run selected mode
        if args.mode == "threat_model":
            run_threat_model(args, api_key)
        elif args.mode == "summary":
            run_summary(args)
        else:
            logger.error("Invalid mode: %s", args.mode)
            sys.exit(1)

    except FileNotFoundError as e:
        logger.error("File not found: %s", e)
        sys.exit(1)
    except ValueError as e:
        logger.error("Value error: %s", e)
        sys.exit(1)
    except PermissionError as e:
        logger.error("Permission error: %s", e)
        sys.exit(1)
    except (RuntimeError, KeyError, AttributeError, TypeError, IOError) as e:
        # Catch specific exceptions instead of a general Exception
        logger.error("Unexpected error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
