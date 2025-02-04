"""Test script to verify package imports."""
import os
import sys
from pathlib import Path

# Add the src directory to Python path
src_path = str(Path(__file__).parent.parent / "src")
sys.path.insert(0, src_path)

def test_imports():
    """Test that all package imports work correctly."""
    try:
        # Try importing the package
        import threat_model
        print("✓ Successfully imported threat_model package")
        
        # Try importing core components
        from threat_model.core import (
            DataProcessor,
            ThreatModelGenerator,
            DEFAULT_MODEL,
            MAX_TOKENS
        )
        print("✓ Successfully imported core components")
        
        # Try creating instances
        processor = DataProcessor()
        generator = ThreatModelGenerator(api_key="test")
        print("✓ Successfully created class instances")
        
        return True
        
    except Exception as e:
        print(f"✗ Import test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)