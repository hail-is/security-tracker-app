"""
Tests for the POAM module.
"""
import pytest
from tools.poam import convert_to_snake_case

@pytest.mark.parametrize("input_str,expected", [
    ("Weakness Name", "weakness_name"),
    ("POAM ID", "poam_id"),
    ("Point of Contact", "point_of_contact"),
    ("CVE", "cve"),
    ("Auto-Approve", "auto_approve"),
    ("Binding Operational Directive 22-01 tracking", "binding_operational_directive_22_01_tracking"),
    ("Last Vendor Check-in Date", "last_vendor_check_in_date"),
    ("Resources Required", "resources_required"),
    ("Overall Remediation Plan", "overall_remediation_plan"),
    ("Original Detection Date", "original_detection_date"),
    ("Status Date", "status_date"),
    ("Vendor Dependency", "vendor_dependency"),
    ("Original Risk Rating", "original_risk_rating"),
    ("False Positive", "false_positive"),
    ("Operational Requirement", "operational_requirement"),
    ("Supporting Documents", "supporting_documents"),
    ("Comments", "comments"),
    ("Service Name", "service_name"),
    # Edge cases
    ("", ""),
    ("alreadysnakecase", "alreadysnakecase"),
    ("UPPER CASE", "upper_case"),
    ("Mixed Case With-Hyphen", "mixed_case_with_hyphen"),
    ("  Spaces  Around  ", "spaces_around"),
    ("multiple   spaces  between", "multiple_spaces_between"),
])
def test_convert_to_snake_case(input_str, expected):
    """Test the convert_to_snake_case function with various inputs."""
    assert convert_to_snake_case(input_str) == expected 