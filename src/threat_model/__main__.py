"""Command line interface for threat model generator."""

import os
import argparse
from pathlib import Path
import logging
from dotenv import load_dotenv

from threat_model.core import ThreatModelGenerator

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Generate threat models for Microsoft 365 and Entra ID")
    parser.add_argument(
        "--mitre-path", type=str, help="Path to MITRE CSV file", default="office_suite_description_mitre_dump.csv"
    )
    parser.add_argument("--idp-path", type=str, help="Path to IDP CSV file", default="idp_description_mitre_dump.csv")
    parser.add_argument(
        "--audit-path", type=str, help="Path to audit operations CSV file", default="audit_operations.csv"
    )
    parser.add_argument("--output", type=str, help="Output file path", default="threat_model.md")
    parser.add_argument("--batch", action="store_true", help="Use batch processing mode")
    parser.add_argument(
        "--sections",
        nargs="+",
        help="Section names for batch processing",
        default=["Authentication Mechanisms", "Data Access Controls", "Application Security"],
    )
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    try:
        # Parse arguments
        args = parse_args()
        # Load environment variables
        load_dotenv()
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")
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
    # Handle exceptions
    except FileNotFoundError as e:
        logger.error("File not found: %s", e)
        raise
    except ValueError as e:
        logger.error("Value error: %s", e)
        raise
    except PermissionError as e:
        logger.error("Permission error: %s", e)
        raise
    except Exception as e:  # disable=E1101
        logger.error("Unexpected error: %s", e)
        raise


if __name__ == "__main__":
    main()
