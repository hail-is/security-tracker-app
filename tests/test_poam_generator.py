"""
Tests for POAM generation functionality.
"""
from datetime import datetime
import pytest
from tools.findings import Finding
from tools.trivy.poam_generator import (
    parse_trivy_id,
    get_next_trivy_id,
    findings_to_poam,
    group_findings_by_weakness,
    generate_poams_from_findings
)

def create_test_finding(finding_id: str, weakness_name: str, asset_identifier: str) -> Finding:
    """Helper to create a test Finding with minimal required fields."""
    return Finding(
        finding_id=finding_id,
        controls="Test controls",
        weakness_name=weakness_name,
        weakness_description="Test description",
        weakness_detector_source="Trivy",
        weakness_source_identifier="TEST-001",
        asset_identifier=asset_identifier,
        point_of_contact="test@example.com",
        resources_required=None,
        overall_remediation_plan="Test plan",
        original_detection_date=datetime.now(),
        scheduled_completion_date=datetime.now(),
        planned_milestones="Test milestones",
        milestone_changes="None",
        status_date=datetime.now(),
        vendor_dependency="None",
        last_vendor_check_in_date=None,
        vendor_dependent_product_name="None",
        original_risk_rating="Low",
        adjusted_risk_rating=None,
        risk_adjustment="None",
        false_positive="No",
        operational_requirement="No",
        deviation_rationale=None,
        supporting_documents=None,
        comments=None,
        auto_approve="No",
        binding_operational_directive_22_01_tracking="No",
        binding_operational_directive_22_01_due_date=None,
        cve=None,
        service_name="test-service"
    )

def test_parse_trivy_id():
    """Test parsing Trivy POAM IDs."""
    # Test valid IDs
    assert parse_trivy_id("2024-TRIVY0001") == (2024, 1)
    assert parse_trivy_id("2023-TRIVY9999") == (2023, 9999)
    
    # Test invalid IDs
    with pytest.raises(ValueError):
        parse_trivy_id("invalid")
    with pytest.raises(ValueError):
        parse_trivy_id("2024-TRIVY")
    with pytest.raises(ValueError):
        parse_trivy_id("2024-trivy0001")

def test_get_next_trivy_id():
    """Test generating next Trivy POAM ID."""
    # Test with no existing IDs
    assert get_next_trivy_id([], 2024) == "2024-TRIVY0001"
    
    # Test with existing IDs
    existing_ids = ["2024-TRIVY0001", "2024-TRIVY0002", "2023-TRIVY0001"]
    assert get_next_trivy_id(existing_ids, 2024) == "2024-TRIVY0003"
    
    # Test with invalid IDs in the list
    existing_ids = ["2024-TRIVY0001", "invalid", "2024-TRIVY0003"]
    assert get_next_trivy_id(existing_ids, 2024) == "2024-TRIVY0004"

def test_findings_to_poam():
    """Test converting findings to a POAM."""
    findings = [
        create_test_finding("TRIVY-001", "SQL Injection", "app-1"),
        create_test_finding("TRIVY-002", "SQL Injection", "app-2")
    ]
    
    poam = findings_to_poam(findings, "2024-TRIVY0001")
    
    # Verify basic fields
    assert poam.poam_id == "2024-TRIVY0001"
    assert poam.weakness_name == "SQL Injection"
    assert poam.asset_identifier == "app-1, app-2"
    assert poam.comments == "TRIVY-001, TRIVY-002"
    
    # Test with different weakness names
    findings = [
        create_test_finding("TRIVY-001", "SQL Injection", "app-1"),
        create_test_finding("TRIVY-002", "XSS", "app-2")
    ]
    with pytest.raises(ValueError):
        findings_to_poam(findings, "2024-TRIVY0001")
    
    # Test with empty findings list
    with pytest.raises(ValueError):
        findings_to_poam([], "2024-TRIVY0001")

def test_group_findings_by_weakness():
    """Test grouping findings by weakness name."""
    findings = [
        create_test_finding("TRIVY-001", "SQL Injection", "app-1"),
        create_test_finding("TRIVY-002", "XSS", "app-2"),
        create_test_finding("TRIVY-003", "SQL Injection", "app-3")
    ]
    
    groups = group_findings_by_weakness(findings)
    
    assert len(groups) == 2
    assert len(groups["SQL Injection"]) == 2
    assert len(groups["XSS"]) == 1
    assert {f.finding_id for f in groups["SQL Injection"]} == {"TRIVY-001", "TRIVY-003"}
    assert {f.finding_id for f in groups["XSS"]} == {"TRIVY-002"}

def test_generate_poams_from_findings():
    """Test generating POAMs from findings."""
    findings = [
        create_test_finding("TRIVY-001", "SQL Injection", "app-1"),
        create_test_finding("TRIVY-002", "XSS", "app-2"),
        create_test_finding("TRIVY-003", "SQL Injection", "app-3")
    ]
    
    existing_poam_ids = ["2024-TRIVY0001", "2024-TRIVY0002"]
    result = generate_poams_from_findings(findings, existing_poam_ids, 2024)
    
    assert len(result) == 2  # Two groups: SQL Injection and XSS
    
    # Check SQL Injection group
    sql_group = next(r for r in result if r[1].weakness_name == "SQL Injection")
    assert len(sql_group[0]) == 2  # Two findings
    assert sql_group[1].poam_id == "2024-TRIVY0003"
    assert sql_group[1].asset_identifier == "app-1, app-3"
    assert sql_group[1].comments == "TRIVY-001, TRIVY-003"
    
    # Check XSS group
    xss_group = next(r for r in result if r[1].weakness_name == "XSS")
    assert len(xss_group[0]) == 1  # One finding
    assert xss_group[1].poam_id == "2024-TRIVY0004"
    assert xss_group[1].asset_identifier == "app-2"
    assert xss_group[1].comments == "TRIVY-002" 