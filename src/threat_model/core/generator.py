"""Threat model generation logic."""

# Standard library imports
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

# Third-party imports
import yaml  # type: ignore
import anthropic
import jinja2

# Local imports
from .config import PROMPTS_DIR, OUTPUT_DIR
from .data_processor import DataProcessor
from .batch_processor import BatchProcessor

logger = logging.getLogger(__name__)


class ThreatModelGenerator:
    """Generates comprehensive threat models using MITRE and audit data."""

    def __init__(self, api_key: str):
        """Initialize the generator.

        Args:
            api_key: Anthropic API key

        Raises:
            ValueError: If API key is empty
        """
        if not api_key:
            raise ValueError("API key cannot be empty")
        self.client = anthropic.Anthropic(api_key=api_key)
        self.data_processor = DataProcessor()
        self.templates = self._load_templates()
        self.batch_processor = BatchProcessor(self.client, self.data_processor)

    def _load_templates(self) -> Dict[str, str]:
        """Load template files.

        Returns:
            Dictionary of template names to template content
        """
        template_path = PROMPTS_DIR / "templates.yaml"
        if not template_path.exists():
            raise FileNotFoundError(f"Templates file not found at {template_path}")
        try:
            with open(template_path) as f:
                templates = yaml.safe_load(f)
                # Ensure all values are strings
                return {k: str(v) for k, v in templates.items()}
        except FileNotFoundError:
            raise
        except Exception as e:  # disable=bare-except # noqa: E722
            logger.error("Error loading templates: %s", str(e))
            raise

    def load_data(self, mitre_path: Path, idp_path: Path, audit_path: Path) -> None:
        """Load and process input data.

        Args:
            mitre_path: Path to MITRE CSV file
            idp_path: Path to IDP CSV file
            audit_path: Path to audit operations CSV file
        """
        self.data_processor.load_csv(mitre_path, "mitre")
        self.data_processor.load_csv(idp_path, "idp")
        self.data_processor.load_csv(audit_path, "audit")
        self.data_processor.correlate_techniques_with_operations()

    def _create_section(self, technique_group: List[str]) -> str:
        """Create content for a threat model section.

        Args:
            technique_group: List of related technique IDs

        Returns:
            Formatted section content
        """
        # Get template
        template = jinja2.Template(self.templates["section_template"])
        # Get technique data
        techniques = []
        for tid in technique_group:
            technique = self.data_processor.mitre_data[self.data_processor.mitre_data["TID"] == tid].iloc[0]
            # Get correlated operations
            operations = self.data_processor.correlation_matrix.get(tid, [])
            techniques.append(
                {
                    "id": tid,
                    "name": technique["Technique"],
                    "description": technique["Description"],
                    "operations": operations,
                }
            )
        # Prepare section data
        section_data = {
            "section_title": f"Attack Vector Group: {techniques[0]['name']}",
            "risk_level": self._calculate_risk_level(techniques),
            "impact": self._calculate_impact(techniques),
            "likelihood": self._calculate_likelihood(techniques),
            "techniques": techniques,
            "operations": self._get_combined_operations(techniques),
            "detection_strategy": self._create_detection_strategy(techniques),
            "controls": self._create_controls(techniques),
        }
        return template.render(**section_data)

    def _calculate_risk_level(self, techniques: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level for a group of techniques.

        Args:
            techniques: List of technique data

        Returns:
            Risk level string
        """
        # Simple scoring based on number of techniques and their correlations
        score = len(techniques)
        for technique in techniques:
            score += len(technique["operations"])
        # Check for high-impact keywords
        if score > 15:
            return "Critical"
        elif score > 10:
            return "High"
        elif score > 5:
            return "Medium"
        else:
            return "Low"

    def _calculate_impact(self, techniques: List[Dict[str, Any]]) -> str:
        """Calculate potential impact of technique group.

        Args:
            techniques: List of technique data

        Returns:
            Impact level string
        """
        # Check for high-impact keywords
        high_impact = ["credentials", "administrator", "privileged", "sensitive"]
        # Check if any technique description contains high-impact keywords
        for technique in techniques:
            desc = technique["description"].lower()
            if any(word in desc for word in high_impact):
                return "High"
        # Default to medium impact
        return "Medium"

    def _calculate_likelihood(self, techniques: List[Dict[str, Any]]) -> str:
        """Calculate likelihood of technique group being used.

        Args:
            techniques: List of technique data

        Returns:
            Likelihood level string
        """
        # Base on number of correlated operations
        total_ops = sum(len(t["operations"]) for t in techniques)
        # Check for high likelihood based on number of operations
        if total_ops > 20:
            return "High"
        elif total_ops > 10:
            return "Medium"
        else:
            return "Low"

    def _get_combined_operations(self, techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get combined and deduplicated operations for technique group.

        Args:
            techniques: List of technique data

        Returns:
            List of operation data
        """
        operations: Dict[str, Dict[str, Any]] = {}
        for technique in techniques:
            for op, score in technique["operations"]:
                if op not in operations or score > operations[op]["score"]:
                    operations[op] = {"operation": op, "score": score, "techniques": [technique["id"]]}
                else:
                    operations[op]["techniques"].append(technique["id"])
        # Sort operations by score
        return sorted(operations.values(), key=lambda x: x["score"], reverse=True)

    def _create_detection_strategy(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create comprehensive detection strategy for technique group.

        Args:
            techniques: List of technique data

        Returns:
            Detection strategy configuration
        """
        operations = self._get_combined_operations(techniques)
        # Create SQL-based detection rules
        return {
            "audit_events": [op["operation"] for op in operations],
            "correlation_rules": [
                {
                    "name": f"Detect {t['name']}",
                    "description": f"Identify potential {t['name']} activity",
                    "operations": [op[0] for op in t["operations"]],
                    "threshold": "medium",
                    "window": "1h",
                }
                for t in techniques
            ],
            "behavioral_analytics": {"baseline_period": "30d", "anomaly_detection": True, "sequence_analysis": True},
        }

    def _create_controls(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create security controls for technique group.

        Args:
            techniques: List of technique data

        Returns:
            Security controls configuration
        """
        return {
            "preventive": [
                {
                    "name": "Access Control",
                    "description": "Implement strict access controls and authentication",
                    "implementation": ["Enable MFA", "Implement least privilege", "Regular access reviews"],
                },
                {
                    "name": "Security Policies",
                    "description": "Configure security policies and restrictions",
                    "implementation": [
                        "Application control policies",
                        "Device compliance policies",
                        "Conditional Access policies",
                    ],
                },
            ],
            "detective": [
                {
                    "name": "Monitoring",
                    "description": "Implement comprehensive monitoring",
                    "implementation": ["Enable audit logging", "Configure alerts", "Regular log review"],
                },
                {
                    "name": "Threat Detection",
                    "description": "Deploy threat detection capabilities",
                    "implementation": [
                        "Enable Microsoft Defender",
                        "Configure detection rules",
                        "Regular threat hunting",
                    ],
                },
            ],
        }

    def generate_threat_model_batch(self, sections: List[str], output_file: str) -> None:
        """Generate threat model using batch processing.

        Args:
            sections: List of section descriptions (ignored, using MITRE techniques instead)
            output_file: Path to output file

        Raises:
            ValueError: If no MITRE techniques are found
            Exception: For other processing errors
        """
        try:
            # Generate and save the threat models using batch processor
            self.batch_processor.generate_threat_models(output_file)
        except ValueError as ve:
            logger.error("Value error: %s", str(ve))
            raise
        except FileNotFoundError as fe:
            logger.error("File not found: %s", str(fe))
            raise
        except IOError as ioe:
            logger.error("IO error: %s", str(ioe))
            raise
        except Exception as e:  # disable=bare-except
            logger.error("Unexpected error: %s", str(e))
            raise

    def generate_threat_model(self, output_dir: Optional[Path] = None) -> str:
        """Generate complete threat model document and save it to file.

        Args:
            output_dir: Optional custom output directory. If not provided, uses OUTPUT_DIR from config.

        Returns:
            Markdown formatted threat model content

        Raises:
            IOError: If there's an error writing the output file
        """
        try:
            # Get technique groups
            groups = self.data_processor.get_technique_groups()
            # Generate content for each group
            sections = []
            for group in groups:
                section = self._create_section(group)
                sections.append(section)
            # Combine sections with main template
            content = "# Microsoft 365 and Entra ID Threat Model\n\n"
            content += "Comprehensive threat model analyzing attack vectors, detection strategies, and controls\n\n"
            content += "\n\n".join(sections)
            # Determine output path
            output_path = (output_dir if output_dir is not None else OUTPUT_DIR) / "threat_model.md"
            # Ensure directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)
            # Write content to file
            logger.info("Writing threat model to %s", output_path)
            try:
                output_path.write_text(content)
                # Verify file was created
                if not output_path.exists():
                    raise IOError(f"Failed to create output file at {output_path}")
                logger.info("Successfully created output file at %s", output_path)
            except Exception as e:
                logger.error("Error writing to file: %s", str(e))
                raise IOError(f"Failed to write output file at {output_path}: {str(e)}")
            logger.info("Threat model successfully generated and saved to %s", output_path)
            return content
        except FileNotFoundError as e:
            logger.error("File not found: %s", str(e))
            raise
        except IOError as e:
            logger.error("IO error: %s", str(e))
            raise
        except ValueError as e:
            logger.error("Value error: %s", str(e))
            raise
        except Exception as e:  # disable=bare-except
            logger.error("Unexpected error generating threat model: %s", str(e))
            raise
