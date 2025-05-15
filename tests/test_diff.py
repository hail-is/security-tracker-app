"""
Tests for the diff logic between Findings and POAMs.
"""
from datetime import datetime
from pathlib import Path

from tools.findings import Finding
from tools.poam import PoamEntry
from tools.trivy.diff import (
    _is_exact_match,
    _is_asset_covered,
    _find_matching_poam,
    compare_findings_to_poams,
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

def create_test_poam(poam_id: str, weakness_name: str, asset_identifier: str) -> PoamEntry:
    """Helper to create a test PoamEntry with minimal required fields."""
    return PoamEntry(
        poam_id=poam_id,
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

def test_exact_match():
    """Test the exact matching function."""
    assert _is_exact_match("Test String", "test string")
    assert _is_exact_match("test string ", "test string")
    assert not _is_exact_match("test string", "different string")
    assert not _is_exact_match("", None)
    assert not _is_exact_match(None, "test")

def test_asset_covered():
    """Test the asset coverage function."""
    # Single asset matches
    assert _is_asset_covered("app-1", "app-1")
    assert _is_asset_covered("app-1", "App-1")
    
    # Asset list includes the finding's asset
    assert _is_asset_covered("app-1", "app-1, app-2, app-3")
    assert _is_asset_covered("app-2", "app-1,app-2,app-3")
    
    # Asset not in list
    assert not _is_asset_covered("app-4", "app-1, app-2, app-3")
    
    # Edge cases
    assert not _is_asset_covered("", "app-1")
    assert not _is_asset_covered("app-1", "")
    assert not _is_asset_covered(None, "app-1")
    assert not _is_asset_covered("app-1", None)

def test_find_matching_poam():
    """Test finding matching POAMs."""
    finding = create_test_finding(
        finding_id="TRIVY-001",
        weakness_name="SQL Injection; CVE-2023-1234",
        asset_identifier="app-1"
    )
    
    # Exact match
    matching_poam = create_test_poam(
        poam_id="POAM-001",
        weakness_name="SQL Injection; CVE-2023-1234",
        asset_identifier="app-1"
    )
    
    # Same weakness, different asset
    different_asset_poam = create_test_poam(
        poam_id="POAM-002",
        weakness_name="SQL Injection; CVE-2023-1234",
        asset_identifier="app-2"
    )
    
    # Different weakness, same asset
    different_weakness_poam = create_test_poam(
        poam_id="POAM-003",
        weakness_name="XSS; CVE-2023-5678",
        asset_identifier="app-1"
    )
    
    # POAM covering multiple assets
    multi_asset_poam = create_test_poam(
        poam_id="POAM-004",
        weakness_name="SQL Injection; CVE-2023-1234",
        asset_identifier="app-1, app-2, app-3"
    )
    
    # Test single POAM matching
    match = _find_matching_poam(finding, [matching_poam])
    assert match is not None
    assert match.poam.poam_id == "POAM-001"
    
    # Test no match for different asset
    match = _find_matching_poam(finding, [different_asset_poam])
    assert match is None
    
    # Test no match for different weakness
    match = _find_matching_poam(finding, [different_weakness_poam])
    assert match is None
    
    # Test match with multi-asset POAM
    match = _find_matching_poam(finding, [multi_asset_poam])
    assert match is not None
    assert match.poam.poam_id == "POAM-004"
    
    # Test finding best match from multiple POAMs
    all_poams = [different_asset_poam, different_weakness_poam, matching_poam, multi_asset_poam]
    match = _find_matching_poam(finding, all_poams)
    assert match is not None
    assert match.poam.poam_id == "POAM-001"  # Should match the first valid match

def test_compare_findings_to_poams():
    """Test the full comparison logic."""
    # Create test findings
    findings = [
        create_test_finding("TRIVY-001", "SQL Injection; CVE-2023-1234", "app-1"),  # Should match open POAM
        create_test_finding("TRIVY-002", "XSS; CVE-2023-5678", "app-2"),           # Should be new (no match)
        create_test_finding("TRIVY-003", "CSRF; CVE-2023-9012", "app-3"),          # Should match open POAM
        create_test_finding("TRIVY-004", "RCE; CVE-2023-4567", "app-4"),           # Should match closed POAM
    ]
    
    # Create test open POAMs
    open_poams = [
        create_test_poam("POAM-001", "SQL Injection; CVE-2023-1234", "app-1, app-4"),  # Should match TRIVY-001
        create_test_poam("POAM-002", "XSS; CVE-2023-5678", "app-5"),                   # Should be closed (no match)
        create_test_poam("POAM-003", "Buffer Overflow; CVE-2023-3456", "app-1"),       # Should be closed (no match)
        create_test_poam("POAM-004", "CSRF; CVE-2023-9012", "app-1, app-2, app-3"),   # Should match TRIVY-003
    ]
    
    # Create test closed POAMs
    closed_poams = [
        create_test_poam("POAM-005", "RCE; CVE-2023-4567", "app-4"),  # Should match TRIVY-004 (reopened)
        create_test_poam("POAM-006", "XSS; CVE-2023-8901", "app-6"),  # Should stay closed (no match)
    ]
    
    # Compare findings to POAMs
    diff = compare_findings_to_poams(findings, open_poams, closed_poams)
    
    # Verify new findings
    assert {f.finding_id for f in diff.new_findings} == {"TRIVY-002"}
    
    # Verify existing matches
    assert {match.poam.poam_id for match in diff.existing_matches} == {"POAM-001", "POAM-004"}
    assert {match.finding.finding_id for match in diff.existing_matches} == {"TRIVY-001", "TRIVY-003"}
    
    # Verify reopened findings
    assert {match.poam.poam_id for match in diff.reopened_findings} == {"POAM-005"}
    assert {match.finding.finding_id for match in diff.reopened_findings} == {"TRIVY-004"}
    
    # Verify closed POAMs
    assert {poam.poam_id for poam in diff.closed_poams} == {"POAM-002", "POAM-003"}
