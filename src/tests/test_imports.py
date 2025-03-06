"""Test script to verify package imports."""

import sys
from pathlib import Path

# Add the src directory to Python path
SRC_PATH = str(Path(__file__).parent.parent / "src")
sys.path.insert(0, SRC_PATH)


def test_imports() -> None:
    """Test that all package imports work correctly."""
    try:
        # Try importing the package
        import threat_model  # pylint: disable=C0415

        # Use proper assertion instead of truthy check
        assert threat_model is not None
        print("✓ Successfully imported threat_model package")

        # Try importing core components
        from threat_model.core import (
            DataProcessor,
            ThreatModelGenerator,
            DEFAULT_MODEL,
            MAX_TOKENS,
        )  # pylint: disable=C0415

        # Verify class existence without truthy check
        assert DataProcessor is not None
        assert ThreatModelGenerator is not None
        assert DEFAULT_MODEL is not None
        assert MAX_TOKENS is not None
        print("✓ Successfully imported core components")

        # Create and verify instances
        processor = DataProcessor()
        generator = ThreatModelGenerator(api_key="test")

        assert isinstance(processor, DataProcessor)
        assert isinstance(generator, ThreatModelGenerator)
        print("✓ Successfully created class instances")

    except Exception as e:  # pylint: disable=W0703
        print(f"✗ Import test failed: {str(e)}")
        import traceback  # pylint: disable=C0415

        traceback.print_exc()
        assert False


if __name__ == "__main__":
    test_imports()
