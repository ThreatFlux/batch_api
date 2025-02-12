"""Core modules for threat model generation."""
import logging

# Configure package logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Import core components
try:
    from .config import (
        DEFAULT_MODEL,
        MAX_TOKENS,
        BATCH_SIZE,
        PROMPTS_DIR,
        OUTPUT_DIR,
        CSV_SETTINGS,
        CORRELATION_WEIGHTS
    )
    from .data_processor import DataProcessor
    from .generator import ThreatModelGenerator
except ImportError as e:
    logger.error("Failed to import core components: %s", e)
    raise

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
    'CORRELATION_WEIGHTS'
]
