"""
Tests for CIS POAM generator.
"""
from datetime import datetime, timedelta, timezone
from tools.findings import Finding
from tools.cis.poam_generator import generate_poams_from_findings

def test_findings_with_same_weakness_are_grouped():
    """Test that findings with the same weakness name and risk rating are grouped into one POAM."""
    detection_date = datetime.now(timezone.utc)
    completion_date = detection_date + timedelta(days=30)
    status_date = detection_date

    # Create two findings with same weakness name and risk rating
    findings = [
        Finding(
            finding_id="finding1",
            controls="",
            weakness_name="[VMS] Ensure that instances are not configured to use the default service account",
            weakness_description="Instance 1 is using default service account",
            weakness_detector_source="CIS",
            weakness_source_identifier="",
            asset_identifier="instance-1",
            point_of_contact="Security Team",
            resources_required="Security Team time",
            overall_remediation_plan="Remediate default service account usage",
            original_detection_date=detection_date,
            scheduled_completion_date=completion_date,
            planned_milestones="",
            milestone_changes="",
            status_date=status_date,
            vendor_dependency="No",
            last_vendor_check_in_date=None,
            vendor_dependent_product_name="",
            original_risk_rating="High",
            adjusted_risk_rating=None,
            risk_adjustment="",
            false_positive="No",
            operational_requirement="No",
            deviation_rationale=None,
            supporting_documents=None,
            comments=None,
            auto_approve="No",
            binding_operational_directive_22_01_tracking="No",
            binding_operational_directive_22_01_due_date=None,
            cve=None,
            service_name=""
        ),
        Finding(
            finding_id="finding2",
            controls="",
            weakness_name="[VMS] Ensure that instances are not configured to use the default service account",
            weakness_description="Instance 2 is using default service account",
            weakness_detector_source="CIS",
            weakness_source_identifier="",
            asset_identifier="instance-2",
            point_of_contact="Security Team",
            resources_required="Security Team time",
            overall_remediation_plan="Remediate default service account usage",
            original_detection_date=detection_date,
            scheduled_completion_date=completion_date,
            planned_milestones="",
            milestone_changes="",
            status_date=status_date,
            vendor_dependency="No",
            last_vendor_check_in_date=None,
            vendor_dependent_product_name="",
            original_risk_rating="High",
            adjusted_risk_rating=None,
            risk_adjustment="",
            false_positive="No",
            operational_requirement="No",
            deviation_rationale=None,
            supporting_documents=None,
            comments=None,
            auto_approve="No",
            binding_operational_directive_22_01_tracking="No",
            binding_operational_directive_22_01_due_date=None,
            cve=None,
            service_name=""
        )
    ]

    # Generate POAMs
    result = generate_poams_from_findings(findings, existing_poam_ids=[])

    # Verify we only got one POAM
    assert len(result) == 1, "Expected findings to be grouped into one POAM"

    # Get the findings and POAM from the result
    grouped_findings, poam = result[0]

    # Verify both findings are in the group
    assert len(grouped_findings) == 2, "Expected both findings in the group"
    assert {f.finding_id for f in grouped_findings} == {"finding1", "finding2"}

    # Verify POAM has combined asset identifiers
    assert "instance-1" in poam.asset_identifier
    assert "instance-2" in poam.asset_identifier
    assert "," in poam.asset_identifier  # Should be comma-separated

    # Verify other POAM fields
    assert poam.weakness_name == "[VMS] Ensure that instances are not configured to use the default service account"
    assert poam.original_risk_rating == "High"
    # Due date should be 30 days from now (for High risk)
    expected_due_date = datetime.now(timezone.utc) + timedelta(days=30)
    assert abs((poam.scheduled_completion_date - expected_due_date).days) <= 1  # Allow 1 day difference due to timing

def test_findings_with_different_weakness_not_grouped():
    """Test that findings with different weakness names are not grouped."""
    detection_date = datetime.now(timezone.utc)
    completion_date = detection_date + timedelta(days=30)
    status_date = detection_date

    # Create two findings with different weakness names
    findings = [
        Finding(
            finding_id="finding1",
            controls="",
            weakness_name="[VMS] Ensure that instances are not configured to use the default service account",
            weakness_description="Instance 1 is using default service account",
            weakness_detector_source="CIS",
            weakness_source_identifier="",
            asset_identifier="instance-1",
            point_of_contact="Security Team",
            resources_required="Security Team time",
            overall_remediation_plan="Remediate default service account usage",
            original_detection_date=detection_date,
            scheduled_completion_date=completion_date,
            planned_milestones="",
            milestone_changes="",
            status_date=status_date,
            vendor_dependency="No",
            last_vendor_check_in_date=None,
            vendor_dependent_product_name="",
            original_risk_rating="High",
            adjusted_risk_rating=None,
            risk_adjustment="",
            false_positive="No",
            operational_requirement="No",
            deviation_rationale=None,
            supporting_documents=None,
            comments=None,
            auto_approve="No",
            binding_operational_directive_22_01_tracking="No",
            binding_operational_directive_22_01_due_date=None,
            cve=None,
            service_name=""
        ),
        Finding(
            finding_id="finding2",
            controls="",
            weakness_name="[VMS] Ensure that instances do not have public IP addresses",
            weakness_description="Instance 2 has public IP",
            weakness_detector_source="CIS",
            weakness_source_identifier="",
            asset_identifier="instance-2",
            point_of_contact="Security Team",
            resources_required="Security Team time",
            overall_remediation_plan="Remove public IP addresses",
            original_detection_date=detection_date,
            scheduled_completion_date=completion_date,
            planned_milestones="",
            milestone_changes="",
            status_date=status_date,
            vendor_dependency="No",
            last_vendor_check_in_date=None,
            vendor_dependent_product_name="",
            original_risk_rating="High",
            adjusted_risk_rating=None,
            risk_adjustment="",
            false_positive="No",
            operational_requirement="No",
            deviation_rationale=None,
            supporting_documents=None,
            comments=None,
            auto_approve="No",
            binding_operational_directive_22_01_tracking="No",
            binding_operational_directive_22_01_due_date=None,
            cve=None,
            service_name=""
        )
    ]

    # Generate POAMs
    result = generate_poams_from_findings(findings, existing_poam_ids=[])

    # Verify we got two POAMs
    assert len(result) == 2, "Expected findings to generate separate POAMs"

    # Verify each POAM has one finding
    for findings_group, poam in result:
        assert len(findings_group) == 1, "Expected one finding per POAM"
        assert poam.asset_identifier in ["instance-1", "instance-2"]
        assert "," not in poam.asset_identifier  # Should not be comma-separated

def test_findings_with_different_risk_ratings_not_grouped():
    """Test that findings with same weakness but different risk ratings are not grouped."""
    detection_date = datetime.now(timezone.utc)
    completion_date = detection_date + timedelta(days=30)
    status_date = detection_date

    # Create two findings with same weakness but different risk ratings
    findings = [
        Finding(
            finding_id="finding1",
            controls="",
            weakness_name="[VMS] Ensure that instances are not configured to use the default service account",
            weakness_description="Instance 1 is using default service account",
            weakness_detector_source="CIS",
            weakness_source_identifier="",
            asset_identifier="instance-1",
            point_of_contact="Security Team",
            resources_required="Security Team time",
            overall_remediation_plan="Remediate default service account usage",
            original_detection_date=detection_date,
            scheduled_completion_date=completion_date,
            planned_milestones="",
            milestone_changes="",
            status_date=status_date,
            vendor_dependency="No",
            last_vendor_check_in_date=None,
            vendor_dependent_product_name="",
            original_risk_rating="High",
            adjusted_risk_rating=None,
            risk_adjustment="",
            false_positive="No",
            operational_requirement="No",
            deviation_rationale=None,
            supporting_documents=None,
            comments=None,
            auto_approve="No",
            binding_operational_directive_22_01_tracking="No",
            binding_operational_directive_22_01_due_date=None,
            cve=None,
            service_name=""
        ),
        Finding(
            finding_id="finding2",
            controls="",
            weakness_name="[VMS] Ensure that instances are not configured to use the default service account",
            weakness_description="Instance 2 is using default service account",
            weakness_detector_source="CIS",
            weakness_source_identifier="",
            asset_identifier="instance-2",
            point_of_contact="Security Team",
            resources_required="Security Team time",
            overall_remediation_plan="Remediate default service account usage",
            original_detection_date=detection_date,
            scheduled_completion_date=completion_date,
            planned_milestones="",
            milestone_changes="",
            status_date=status_date,
            vendor_dependency="No",
            last_vendor_check_in_date=None,
            vendor_dependent_product_name="",
            original_risk_rating="Low",  # Different risk rating
            adjusted_risk_rating=None,
            risk_adjustment="",
            false_positive="No",
            operational_requirement="No",
            deviation_rationale=None,
            supporting_documents=None,
            comments=None,
            auto_approve="No",
            binding_operational_directive_22_01_tracking="No",
            binding_operational_directive_22_01_due_date=None,
            cve=None,
            service_name=""
        )
    ]

    # Generate POAMs
    result = generate_poams_from_findings(findings, existing_poam_ids=[])

    # Verify we got two POAMs (due to different completion dates)
    assert len(result) == 2, "Expected findings to generate separate POAMs due to different risk ratings"

    # Verify completion dates are different
    completion_dates = {poam.scheduled_completion_date for _, poam in result}
    assert len(completion_dates) == 2, "Expected different completion dates for different risk ratings" 