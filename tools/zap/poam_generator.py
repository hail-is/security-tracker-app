"""
Module for generating POAMs from ZAP findings.
"""
from datetime import datetime
from typing import List, Dict, Tuple
import re
from ..findings import Finding
from ..poam import PoamEntry

def parse_zap_id(poam_id: str) -> Tuple[int, int]:
    """
    Parse a ZAP POAM ID into year and sequence components.
    
    Args:
        poam_id: POAM ID in format YYYY-ZAPXXXX
        
    Returns:
        Tuple of (year, sequence_number)
        
    Raises:
        ValueError: If the ID format is invalid
    """
    match = re.match(r'^(\d{4})-ZAP(\d{4,})$', poam_id)
    if not match:
        raise ValueError(f"Invalid ZAP POAM ID format: {poam_id}")
    
    year = int(match.group(1))
    sequence = int(match.group(2))
    return year, sequence

def get_next_zap_id(existing_poam_ids: List[str], current_year: int = None) -> str:
    """
    Generate the next available ZAP POAM ID.
    
    Args:
        existing_poam_ids: List of existing POAM IDs
        current_year: Optional year to use (defaults to current year)
        
    Returns:
        Next available POAM ID in format YYYY-ZAPXXXX
    """
    current_year = datetime.now().year if current_year is None else current_year
    
    # Find highest sequence number for the current year
    max_sequence = 0
    for poam_id in existing_poam_ids:
        try:
            year, sequence = parse_zap_id(poam_id)
            if year == current_year:
                max_sequence = max(max_sequence, sequence)
        except ValueError:
            continue  # Skip non-ZAP IDs
    
    return f"{current_year}-ZAP{max_sequence + 1:04d}"

def findings_to_poam(findings: List[Finding], poam_id: str) -> PoamEntry:
    """
    Convert a list of findings with the same weakness into a single POAM.
    
    Args:
        findings: List of findings with the same weakness
        poam_id: POAM ID to use for the new POAM
        
    Returns:
        PoamEntry combining all findings
        
    Raises:
        ValueError: If findings have different weakness names
    """
    if not findings:
        raise ValueError("Cannot create POAM from empty findings list")
    
    # Verify all findings have the same weakness name
    weakness_name = findings[0].weakness_name
    if not all(f.weakness_name == weakness_name for f in findings):
        raise ValueError("All findings must have the same weakness name")
    
    # Combine asset identifiers and finding IDs
    asset_identifiers = [f.asset_identifier for f in findings]
    finding_ids = [f.finding_id for f in findings]
    
    # Use the first finding as a template
    first = findings[0]
    return PoamEntry(
        poam_id=poam_id,
        controls=first.controls,
        weakness_name=first.weakness_name,
        weakness_description=first.weakness_description,
        weakness_detector_source=first.weakness_detector_source,
        weakness_source_identifier=first.weakness_source_identifier,
        asset_identifier=", ".join(asset_identifiers),
        point_of_contact=first.point_of_contact,
        resources_required=first.resources_required,
        overall_remediation_plan=first.overall_remediation_plan,
        original_detection_date=first.original_detection_date,
        scheduled_completion_date=first.scheduled_completion_date,
        planned_milestones=first.planned_milestones,
        milestone_changes=first.milestone_changes,
        status_date=first.status_date,
        vendor_dependency=first.vendor_dependency,
        last_vendor_check_in_date=first.last_vendor_check_in_date,
        vendor_dependent_product_name=first.vendor_dependent_product_name,
        original_risk_rating=first.original_risk_rating,
        adjusted_risk_rating=first.adjusted_risk_rating,
        risk_adjustment=first.risk_adjustment,
        false_positive=first.false_positive,
        operational_requirement=first.operational_requirement,
        deviation_rationale=first.deviation_rationale,
        supporting_documents=first.supporting_documents,
        comments=", ".join(finding_ids),  # Store finding IDs in comments
        auto_approve=first.auto_approve,
        binding_operational_directive_22_01_tracking=first.binding_operational_directive_22_01_tracking,
        binding_operational_directive_22_01_due_date=first.binding_operational_directive_22_01_due_date,
        cve=first.cve,
        service_name=first.service_name
    )

def group_findings_by_weakness(findings: List[Finding]) -> Dict[str, List[Finding]]:
    """
    Group findings by weakness name.
    
    Args:
        findings: List of findings to group
        
    Returns:
        Dictionary mapping weakness names to lists of findings, with findings sorted by ID
    """
    groups: Dict[str, List[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.weakness_name, []).append(finding)
    
    # Sort each group by finding ID
    for findings_list in groups.values():
        findings_list.sort(key=lambda f: f.finding_id)
    
    return groups

def generate_poams_from_findings(findings: List[Finding], existing_poam_ids: List[str], current_year: int = None) -> List[Tuple[List[Finding], PoamEntry]]:
    """
    Generate new POAMs from a list of findings.
    
    Args:
        findings: List of findings to convert to POAMs
        existing_poam_ids: List of existing POAM IDs
        current_year: Optional year to use (defaults to current year)
        
    Returns:
        List of tuples containing (findings_list, generated_poam), sorted by first finding ID
    """
    # Group findings by weakness
    grouped_findings = group_findings_by_weakness(findings)
    
    # Sort groups by the first finding ID in each group
    sorted_groups = sorted(
        grouped_findings.values(),
        key=lambda findings_list: findings_list[0].finding_id if findings_list else ""
    )
    
    # Generate POAMs for each group
    result = []
    current_year = datetime.now().year if current_year is None else current_year
    next_id = get_next_zap_id(existing_poam_ids, current_year)
    
    for findings_list in sorted_groups:
        poam = findings_to_poam(findings_list, next_id)
        result.append((findings_list, poam))
        
        # Get next ID for the next group
        next_id = get_next_zap_id([*existing_poam_ids, next_id], current_year)
    
    return result 