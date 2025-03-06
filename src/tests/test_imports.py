"""Test script to verify package imports."""

import sys
from pathlib import Path

# Add the src directory to Python path
SRC_PATH = str(Path(__file__).parent.parent / "src")
sys.path.insert(0, SRC_PATH)


def test_imports():
    """Test that all package imports work correctly."""
    try:
        # Try importing the package
        import threat_model  # pylint: disable=C0415

        if not threat_model:
            assert False
        print("✓ Successfully imported threat_model package")
        # Try importing core components
        from threat_model.core import (
            DataProcessor,
            ThreatModelGenerator,
            DEFAULT_MODEL,
            MAX_TOKENS,
        )  # pylint: disable=C0415

        if not DataProcessor or not ThreatModelGenerator:
            assert False
        if not DEFAULT_MODEL or not MAX_TOKENS:
            assert False
        print("✓ Successfully imported core components")
        # Try creating instances
        processor = DataProcessor()
        if not processor:
            assert False
        generator = ThreatModelGenerator(api_key="test")
        if not generator:
            assert False
        print("✓ Successfully created class instances")
        assert True

    except Exception as e:
        print(f"✗ Import test failed: {str(e)}")
        import traceback  # pylint: disable=C0415

        traceback.print_exc()
        assert False


if __name__ == "__main__":
    test_imports()
