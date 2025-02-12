"""Configuration settings for the threat model generator."""
from pathlib import Path
from typing import Dict, Any

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
PROMPTS_DIR = PROJECT_ROOT / "src/threat_model/prompts"
OUTPUT_DIR = PROJECT_ROOT / "output"

# Model settings
DEFAULT_MODEL = "claude-3-5-sonnet-20241022"
MAX_TOKENS = 8192
BATCH_SIZE = 100  # Increased batch size for more efficient processing

# Data processing settings
CSV_SETTINGS: Dict[str, Any] = {
    "mitre": {
        "required_columns": ["TID", "Tactic", "Technique", "Description"],
        "index_column": "TID",
        "encoding": "utf-8"
    },
    "idp": {
        "required_columns": ["TID", "Tactic", "Technique", "Description"],
        "index_column": "TID",
        "encoding": "utf-8"
    },
    "audit": {
        "required_columns": ["FriendlyName", "Operation", "Description"],
        "index_column": "Operation",
        "encoding": "utf-8"
    }
}

# Correlation settings
CORRELATION_WEIGHTS = {
    "exact_match": 1.0,
    "partial_match": 0.5,
    "description_similarity": 0.3
}

# Logging settings
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_LEVEL = "INFO"

# File patterns
MITRE_FILE_PATTERN = "*mitre_dump.csv"
AUDIT_FILE_PATTERN = "audit_operations.csv"

# Output settings
THREAT_MODEL_TEMPLATE = "threat_model_template.md"
OUTPUT_FILE = "threat_model.md"

# Cache settings
CACHE_DIR = PROJECT_ROOT / ".cache"
CACHE_EXPIRY = 3600  # 1 hour in seconds

# API settings
API_RETRY_ATTEMPTS = 3
API_RETRY_DELAY = 1  # seconds
