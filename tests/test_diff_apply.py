"""
Tests for diff_apply module.
"""
import json
import tempfile
from pathlib import Path
import pytest
from tools.diff_apply import merge_diffs


def test_merge_diffs_single_file():
    """Test merging a single diff file."""
    # Create a temporary diff file
    diff_data = {
        "new_poams": [{"poam_id": "2025-TEST001", "weakness_name": "Test Weakness"}],
        "reopen_poams": [],
        "close_poams": ["2025-OLD001"],
        "proposed_configuration_findings": [],
        "closed_configuration_findings": []
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(diff_data, f)
        temp_file = Path(f.name)
    
    try:
        result = merge_diffs([temp_file])
        
        assert result["new_poams"] == [{"poam_id": "2025-TEST001", "weakness_name": "Test Weakness"}]
        assert result["reopen_poams"] == []
        assert result["close_poams"] == ["2025-OLD001"]
        assert result["proposed_configuration_findings"] == []
        assert result["closed_configuration_findings"] == []
    finally:
        temp_file.unlink()


def test_merge_diffs_multiple_files():
    """Test merging multiple diff files."""
    # Create first diff file
    diff1_data = {
        "new_poams": [{"poam_id": "2025-TEST001", "weakness_name": "Test Weakness 1"}],
        "reopen_poams": [{"poam_id": "2025-REOPEN001"}],
        "close_poams": ["2025-OLD001"],
        "proposed_configuration_findings": [],
        "closed_configuration_findings": []
    }
    
    # Create second diff file
    diff2_data = {
        "new_poams": [{"poam_id": "2025-TEST002", "weakness_name": "Test Weakness 2"}],
        "reopen_poams": [],
        "close_poams": ["2025-OLD002"],
        "proposed_configuration_findings": [{"poam_id": "2025-CIS001", "weakness_name": "Config Issue"}],
        "closed_configuration_findings": []
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f1:
        json.dump(diff1_data, f1)
        temp_file1 = Path(f1.name)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f2:
        json.dump(diff2_data, f2)
        temp_file2 = Path(f2.name)
    
    try:
        result = merge_diffs([temp_file1, temp_file2])
        
        # Check that all items from both files are merged
        assert len(result["new_poams"]) == 2
        assert {"poam_id": "2025-TEST001", "weakness_name": "Test Weakness 1"} in result["new_poams"]
        assert {"poam_id": "2025-TEST002", "weakness_name": "Test Weakness 2"} in result["new_poams"]
        
        assert len(result["reopen_poams"]) == 1
        assert {"poam_id": "2025-REOPEN001"} in result["reopen_poams"]
        
        assert len(result["close_poams"]) == 2
        assert "2025-OLD001" in result["close_poams"]
        assert "2025-OLD002" in result["close_poams"]
        
        assert len(result["proposed_configuration_findings"]) == 1
        assert {"poam_id": "2025-CIS001", "weakness_name": "Config Issue"} in result["proposed_configuration_findings"]
        
        assert result["closed_configuration_findings"] == []
    finally:
        temp_file1.unlink()
        temp_file2.unlink()


def test_merge_diffs_empty_lists():
    """Test merging files with empty lists."""
    diff_data = {
        "new_poams": [],
        "reopen_poams": [],
        "close_poams": [],
        "proposed_configuration_findings": [],
        "closed_configuration_findings": []
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(diff_data, f)
        temp_file = Path(f.name)
    
    try:
        result = merge_diffs([temp_file])
        
        assert result["new_poams"] == []
        assert result["reopen_poams"] == []
        assert result["close_poams"] == []
        assert result["proposed_configuration_findings"] == []
        assert result["closed_configuration_findings"] == []
    finally:
        temp_file.unlink()


def test_merge_diffs_no_files():
    """Test that merge_diffs raises error with no files."""
    with pytest.raises(ValueError, match="No diff files provided"):
        merge_diffs([])


def test_merge_diffs_nonexistent_file():
    """Test that merge_diffs raises error with nonexistent file."""
    with pytest.raises(ValueError, match="Diff file does not exist"):
        merge_diffs([Path("nonexistent.json")])


def test_merge_diffs_invalid_json():
    """Test that merge_diffs raises error with invalid JSON."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("invalid json content")
        temp_file = Path(f.name)
    
    try:
        with pytest.raises(ValueError, match="Error reading diff file"):
            merge_diffs([temp_file])
    finally:
        temp_file.unlink()


def test_merge_diffs_missing_keys():
    """Test merging files with missing keys (should be handled gracefully)."""
    # File with only some keys
    diff_data = {
        "new_poams": [{"poam_id": "2025-TEST001"}],
        "close_poams": ["2025-OLD001"]
        # Missing other keys
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(diff_data, f)
        temp_file = Path(f.name)
    
    try:
        result = merge_diffs([temp_file])
        
        assert result["new_poams"] == [{"poam_id": "2025-TEST001"}]
        assert result["close_poams"] == ["2025-OLD001"]
        assert result["reopen_poams"] == []
        assert result["proposed_configuration_findings"] == []
        assert result["closed_configuration_findings"] == []
    finally:
        temp_file.unlink()
