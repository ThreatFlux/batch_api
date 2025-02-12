"""Threat model generation logic."""
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
import anthropic
import jinja2
from anthropic import RateLimitError
from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
from anthropic.types.messages.batch_create_params import Request

from .config import (
    DEFAULT_MODEL,
    MAX_TOKENS,
    BATCH_SIZE,
    PROMPTS_DIR,
    OUTPUT_DIR
)
from .data_processor import DataProcessor

logger = logging.getLogger(__name__)

class ThreatModelGenerator:
    """Generates comprehensive threat models using MITRE and audit data."""
    def __init__(self, api_key: str):
        """Initialize the generator.
        
        Args:
            api_key: Anthropic API key
        """
        self.client = anthropic.Anthropic(api_key=api_key)
        self.data_processor = DataProcessor()
        self.templates = self._load_templates()
    def _load_templates(self) -> Dict[str, str]:
        """Load template files.
        
        Returns:
            Dictionary of template names to template content
        """
        template_path = PROMPTS_DIR / "templates.yaml"
        try:
            with open(template_path) as f:
                templates = yaml.safe_load(f)
                # Ensure all values are strings
                return {k: str(v) for k, v in templates.items()}
        except Exception as e:
            logger.error(f"Error loading templates: {str(e)}")
            raise
    def load_data(self, mitre_path: Path, idp_path: Path, audit_path: Path) -> None:
        """Load and process input data.
        
        Args:
            mitre_path: Path to MITRE CSV file
            idp_path: Path to IDP CSV file
            audit_path: Path to audit operations CSV file
        """
        self.data_processor.load_csv(mitre_path, 'mitre')
        self.data_processor.load_csv(idp_path, 'idp')
        self.data_processor.load_csv(audit_path, 'audit')
        self.data_processor.correlate_techniques_with_operations()
    def _create_section(self, technique_group: List[str]) -> str:
        """Create content for a threat model section.
        
        Args:
            technique_group: List of related technique IDs
            
        Returns:
            Formatted section content
        """
        # Get template
        template = jinja2.Template(self.templates['section_template'])
        # Get technique data
        techniques = []
        for tid in technique_group:
            technique = self.data_processor.mitre_data[
                self.data_processor.mitre_data['TID'] == tid
            ].iloc[0]
            # Get correlated operations
            operations = self.data_processor.correlation_matrix.get(tid, [])
            techniques.append({
                'id': tid,
                'name': technique['Technique'],
                'description': technique['Description'],
                'operations': operations
            })
        # Prepare section data
        section_data = {
            'section_title': f"Attack Vector Group: {techniques[0]['name']}",
            'risk_level': self._calculate_risk_level(techniques),
            'impact': self._calculate_impact(techniques),
            'likelihood': self._calculate_likelihood(techniques),
            'techniques': techniques,
            'operations': self._get_combined_operations(techniques),
            'detection_strategy': self._create_detection_strategy(techniques),
            'controls': self._create_controls(techniques)
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
            score += len(technique['operations'])
        # Check for high-impact keywords
        if score > 15:
            return "Critical"
        elif score > 10:
            return "High"
        elif score > 5:
            return "Medium"
        return "Low"
    def _calculate_impact(self, techniques: List[Dict[str, Any]]) -> str:
        """Calculate potential impact of technique group.
        
        Args:
            techniques: List of technique data
            
        Returns:
            Impact level string
        """
        # Check for high-impact keywords
        high_impact = ['credentials', 'administrator', 'privileged', 'sensitive']
        # Check if any technique description contains high-impact keywords
        for technique in techniques:
            desc = technique['description'].lower()
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
        total_ops = sum(len(t['operations']) for t in techniques)
        # Check for high likelihood based on number of operations
        if total_ops > 20:
            return "High"
        elif total_ops > 10:
            return "Medium"
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
            for op, score in technique['operations']:
                if op not in operations or score > operations[op]['score']:
                    operations[op] = {
                        'operation': op,
                        'score': score,
                        'techniques': [technique['id']]
                    }
                else:
                    operations[op]['techniques'].append(technique['id'])
        # Sort operations by score
        return sorted(operations.values(), key=lambda x: x['score'], reverse=True)
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
            'audit_events': [op['operation'] for op in operations],
            'correlation_rules': [
                {
                    'name': f"Detect {t['name']}",
                    'description': f"Identify potential {t['name']} activity",
                    'operations': [op[0] for op in t['operations']],
                    'threshold': 'medium',
                    'window': '1h'
                }
                for t in techniques
            ],
            'behavioral_analytics': {
                'baseline_period': '30d',
                'anomaly_detection': True,
                'sequence_analysis': True
            }
        }
    def _create_controls(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create security controls for technique group.
        
        Args:
            techniques: List of technique data
            
        Returns:
            Security controls configuration
        """
        return {
            'preventive': [
                {
                    'name': 'Access Control',
                    'description': 'Implement strict access controls and authentication',
                    'implementation': [
                        'Enable MFA',
                        'Implement least privilege',
                        'Regular access reviews'
                    ]
                },
                {
                    'name': 'Security Policies',
                    'description': 'Configure security policies and restrictions',
                    'implementation': [
                        'Application control policies',
                        'Device compliance policies',
                        'Conditional Access policies'
                    ]
                }
            ],
            'detective': [
                {
                    'name': 'Monitoring',
                    'description': 'Implement comprehensive monitoring',
                    'implementation': [
                        'Enable audit logging',
                        'Configure alerts',
                        'Regular log review'
                    ]
                },
                {
                    'name': 'Threat Detection',
                    'description': 'Deploy threat detection capabilities',
                    'implementation': [
                        'Enable Microsoft Defender',
                        'Configure detection rules',
                        'Regular threat hunting'
                    ]
                }
            ]
        }
    def _create_technique_prompt(self, technique_id: str, audit_ops: dict) -> str:
        """Create a detailed prompt for a specific MITRE technique.
        
        Args:
            technique_id: The MITRE technique ID
            audit_ops: Dictionary of audit operations
            
        Returns:
            Formatted prompt string
        """
        # Get technique data
        technique_df = self.data_processor.mitre_data[
            self.data_processor.mitre_data['TID'] == technique_id
        ]
        # Check if technique exists
        if technique_df.empty:
            raise ValueError(f"No technique found with ID: {technique_id}")
        # Extract technique data
        technique_data = technique_df.iloc[0]
        # Find relevant audit operations
        relevant_ops = [
            op for op, details in audit_ops.items()
            if any(term in details['Description'].lower()
                for term in technique_data['Description'].lower().split())
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
    def _create_batch_request(self, section_data: str, custom_id: str) -> Dict[str, Any]:
        """Create a single batch request with proper system messages.
        
        Args:
            section_data: Content for this section
            custom_id: Unique identifier for this request
            
        Returns:
            Configured batch request
        """
        # Convert audit ops data to a more structured format
        formatted_audit_ops = {}
        for _, row in self.data_processor.audit_data.iterrows():
            formatted_audit_ops[row.get('Operation', '')] = {
                'FriendlyName': row.get('FriendlyName', ''),
                'Description': row.get('Description', '')
            }
        # Create system prompt
        system_prompt = (
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
        # Create request
        return {
            'custom_id': custom_id,
            'params': {
                'model': DEFAULT_MODEL,
                'max_tokens': MAX_TOKENS,
                'system': system_prompt,
                'messages': [{
                    "role": "user",
                    "content": self._create_technique_prompt(section_data, formatted_audit_ops)
                }]
            }
        }
    def generate_threat_model_batch(self, sections: List[str], output_file: str) -> None:
        """Generate threat model using batch processing.
        
        Args:
            sections: List of section descriptions (ignored, using MITRE techniques instead)
            output_file: Path to output file
        """
        try:
            # Get available technique IDs from MITRE data
            technique_ids = self.data_processor.mitre_data['TID'].unique().tolist()
            logger.info(f"Found {len(technique_ids)} MITRE techniques")
            # Check if any techniques are available
            if not technique_ids:
                raise ValueError("No MITRE techniques found in data")
            # Process all techniques in batches
            total_techniques = len(technique_ids)
            processed_techniques = 0
            all_content = {}
            while processed_techniques < total_techniques:
                batch_start = processed_techniques
                batch_end = min(batch_start + BATCH_SIZE, total_techniques)
                current_batch = technique_ids[batch_start:batch_end]
                logger.info(f"Processing batch {batch_start//BATCH_SIZE + 1} of {(total_techniques-1)//BATCH_SIZE + 1}")
                logger.info(f"Techniques {batch_start + 1} to {batch_end} of {total_techniques}")
                # Create batch requests for current batch
                requests = []
                for i, technique_id in enumerate(current_batch):
                    try:
                        request = self._create_batch_request(
                            technique_id,
                            f"technique_{batch_start + i}"
                        )
                        requests.append(request)
                        logger.info(f"Created request for technique {technique_id}")
                    except Exception as e:
                        logger.error(f"Error creating request for technique {technique_id}: {str(e)}")
                        continue
                if not requests:
                    logger.error(f"No valid requests created for batch {batch_start//BATCH_SIZE + 1}")
                    processed_techniques = batch_end
                    continue
                # Process current batch
                try:
                    # Convert dictionary requests to Request objects
                    request_objects = []
                    for req in requests:
                        params = MessageCreateParamsNonStreaming(
                            model=req['params']['model'],
                            max_tokens=req['params']['max_tokens'],
                            system=req['params']['system'],
                            messages=req['params']['messages']
                        )
                        request_objects.append(Request(
                            custom_id=req['custom_id'],
                            params=params
                        ))
                    # Submit batch request
                    message_batch = self.client.messages.batches.create(requests=request_objects)
                    logger.info(f"Batch submitted successfully. Batch ID: {message_batch.id}")
                    # Wait for completion
                    while True:
                        try:
                            batch_status = self.client.messages.batches.retrieve(message_batch.id)
                            if batch_status.processing_status == "ended":
                                logger.info(f"Batch {message_batch.id} processing completed")
                                break
                            logger.info(f"Batch {message_batch.id} still processing. Waiting 60 seconds.")
                            time.sleep(60)
                        except Exception as e:
                            logger.error(f"Error checking batch status: {str(e)}")
                            time.sleep(60)
                    # Process batch results
                    for result in self.client.messages.batches.results(message_batch.id):
                        if result.result.type == "succeeded":
                            message_content = result.result.message.content
                            section_text = []
                            for content_item in message_content:
                                if content_item.type == "text":
                                    section_text.append(content_item.text)
                            all_content[result.custom_id] = "\n".join(section_text)
                        else:
                            logger.error(f"Request {result.custom_id} failed with type: {result.result.type}")
                            if result.result.type == "errored":
                                logger.error(f"Error details: {result.result.error}")
                except RateLimitError as e:
                    logger.error("Rate limit exceeded. Retrying in 60 seconds. %s", str(e))
                    time.sleep(60)
                except Exception as e: # disable=bare-except
                    logger.error(f"Error processing batch {batch_start//BATCH_SIZE + 1}: {str(e)}")
                processed_techniques = batch_end
                logger.info(f"Completed {processed_techniques} of {total_techniques} techniques")
            # Save accumulated results
            with open(output_file, 'w') as f:
                # Write introduction
                f.write("# Microsoft 365 & Entra ID Threat Models\n\n")
                f.write("This document contains detailed threat models for specific MITRE ATT&CK techniques ")
                f.write("relevant to Microsoft 365 and Entra ID environments.\n\n")
                f.write("Each model includes:\n")
                f.write("- Detailed attack vectors with example audit logs\n")
                f.write("- SQL-based detection strategies\n")
                f.write("- JSON-formatted technical controls\n")
                f.write("- Specific incident response playbooks\n")
                f.write("- Relevant references and documentation\n\n")
                # Write table of contents
                f.write("## Table of Contents\n\n")
                sorted_techniques = sorted(all_content.items(), key=lambda x: int(x[0].split('_')[1]))
                for technique_id, content in sorted_techniques:
                    # Extract title from content
                    title = next((line for line in content.split('\n') if line.startswith('# Threat Model:')), '')
                    if title:
                        title = title.replace('# Threat Model: ', '')
                        anchor = title.lower().replace(' ', '-').replace('(', '').replace(')', '').replace('.', '')
                        f.write(f"- [{title}](#{anchor})\n")
                f.write("\n---\n\n")
                # Write technique content
                for _, technique_content in sorted_techniques:
                    f.write(f"{technique_content}\n\n")
                    f.write("---\n\n")
            logger.info(f"Threat model saved to {output_file}")
            logger.info(f"Generated {len(all_content)} technique-specific threat models")
            logger.info("Added table of contents with navigation links")
        except Exception as e:
            logger.error(f"Error generating threat model: {str(e)}")
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
            logger.info(f"Writing threat model to {output_path}")
            try:
                output_path.write_text(content)
                # Verify file was created
                if not output_path.exists():
                    raise IOError(f"Failed to create output file at {output_path}")
                logger.info(f"Successfully wrote threat model to {output_path}")
            except Exception as e:
                logger.error(f"Error writing threat model to {output_path}: {str(e)}")
                raise IOError(f"Failed to write output file at {output_path}: {str(e)}")
            logger.info(f"Threat model successfully generated and saved to {output_path}")
            return content
        except FileNotFoundError as e:
            logger.error(f"File not found: {str(e)}")
            raise
        except IOError as e:
            logger.error(f"IO error: {str(e)}")
            raise
        except ValueError as e:
            logger.error(f"Value error: {str(e)}")
            raise
        except Exception as e: # disable=bare-except
            logger.error(f"Error generating threat model: {str(e)}")
            raise
