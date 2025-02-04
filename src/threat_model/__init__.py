"""Threat model generation package for Microsoft 365 and Entra ID."""
import logging
from pathlib import Path

# Configure package logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Import core components
from .core import (
    DataProcessor,
    ThreatModelGenerator,
    DEFAULT_MODEL,
    MAX_TOKENS,
    BATCH_SIZE,
    PROMPTS_DIR,
    OUTPUT_DIR,
    CSV_SETTINGS,
    CORRELATION_WEIGHTS
)

# Package metadata
__version__ = "0.1.0"
__author__ = "Security Team"

# Define package root directory
PACKAGE_ROOT = Path(__file__).parent

# Define public API
__all__ = [
    'DataProcessor',
    'ThreatModelGenerator',
    'DEFAULT_MODEL',
    'MAX_TOKENS',
    'BATCH_SIZE',
    'PROMPTS_DIR',
    'OUTPUT_DIR',
    'CSV_SETTINGS',
    'CORRELATION_WEIGHTS',
    'PACKAGE_ROOT',
    '__version__',
    '__author__'
]