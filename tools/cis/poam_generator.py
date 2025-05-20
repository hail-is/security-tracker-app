"""
Module for generating POAMs from CIS findings.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Tuple, Dict
from collections import defaultdict

from ..findings import Finding
from ..poam import PoamEntry

def _get_next_poam_id(existing_poam_ids: List[str], current_year: int = None) -> str:
    """
    Generate the next available POAM ID for CIS findings.
    
    Args:
        existing_poam_ids: List of existing POAM IDs
        current_year: Year to use for POAM ID (defaults to current year)
        
    Returns:
        Next available POAM ID in format YYYY-CISXXXX
    """
    if current_year is None:
        current_year = datetime.now(timezone.utc).year
        
    # Filter to just this year's CIS POAMs
    year_prefix = f"{current_year}-CIS"
    year_poams = [p for p in existing_poam_ids if p.startswith(year_prefix)]
    
    if not year_poams:
        # First POAM for this year
        return f"{year_prefix}0001"
        
    # Get highest number used
    highest = max(int(p[-4:]) for p in year_poams)
    
    # Return next number
    return f"{year_prefix}{highest + 1:04d}"

def _get_completion_date(risk_rating: str) -> datetime:
    """
    Calculate completion date based on risk rating.
    
    Args:
        risk_rating: Risk rating of the finding
        
    Returns:
        Datetime object for completion date
    """
    today = datetime.now(timezone.utc)
    
    if risk_rating.lower() == "critical":
        return today + timedelta(days=15)
    elif risk_rating.lower() == "high":
        return today + timedelta(days=30)
    elif risk_rating.lower() == "moderate":
        return today + timedelta(days=90)
    else:  # Low
        return today + timedelta(days=180)

def _group_findings_by_weakness_and_date(findings: List[Finding]) -> Dict[tuple, List[Finding]]:
    """
    Group findings by weakness name and completion date.
    
    Args:
        findings: List of findings to group
        
    Returns:
        Dictionary mapping (weakness_name, completion_date) to list of findings
    """
    groups = defaultdict(list)
    for finding in findings:
        completion_date = _get_completion_date(finding.original_risk_rating)
        # Use only the date part for grouping key, but store the full datetime with the finding
        key = (finding.weakness_name, completion_date.date())
        groups[key].append((finding, completion_date))
    return dict(groups)

def generate_poams_from_findings(findings: List[Finding], existing_poam_ids: List[str], current_year: int = None) -> List[Tuple[List[Finding], PoamEntry]]:
    """
    Generate POAMs from CIS findings.
    
    Args:
        findings: List of findings to generate POAMs for
        existing_poam_ids: List of existing POAM IDs
        current_year: Year to use for POAM IDs (defaults to current year)
        
    Returns:
        List of tuples containing (findings, generated_poam)
    """
    result = []
    
    # Group findings by weakness name and completion date
    grouped_findings = _group_findings_by_weakness_and_date(findings)
    
    for (weakness_name, _), group in grouped_findings.items():
        # Unpack findings and their completion dates
        findings_list = [f for f, _ in group]
        first_finding = findings_list[0]
        completion_date = first_finding.scheduled_completion_date
        
        # Get earliest detection date from group
        detection_date = min(f.original_detection_date for f in findings_list)
        
        # Get highest risk rating from group
        risk_rating = max(f.original_risk_rating for f in findings_list)
        
        # Combine asset identifiers
        asset_ids = sorted(set(f.asset_identifier for f in findings_list))
        combined_asset_id = ", ".join(asset_ids)
        
        # Generate POAM ID
        poam_id = _get_next_poam_id(existing_poam_ids, current_year)
        existing_poam_ids.append(poam_id)  # Add to list so next ID will be different
        
        # Create POAM entry
        poam = PoamEntry(
            poam_id=poam_id,
            controls=first_finding.controls,
            weakness_name=first_finding.weakness_name,
            weakness_description=first_finding.weakness_description,
            weakness_detector_source=first_finding.weakness_detector_source,
            weakness_source_identifier=first_finding.weakness_source_identifier,
            asset_identifier=combined_asset_id,
            point_of_contact=first_finding.point_of_contact,
            resources_required=first_finding.resources_required,
            overall_remediation_plan=first_finding.overall_remediation_plan,
            original_detection_date=detection_date,
            scheduled_completion_date=completion_date,
            planned_milestones=first_finding.planned_milestones,
            milestone_changes=first_finding.milestone_changes,
            status_date=datetime.now(timezone.utc),
            vendor_dependency=first_finding.vendor_dependency,
            last_vendor_check_in_date=first_finding.last_vendor_check_in_date,
            vendor_dependent_product_name=first_finding.vendor_dependent_product_name,
            original_risk_rating=risk_rating,
            adjusted_risk_rating=first_finding.adjusted_risk_rating,
            risk_adjustment=first_finding.risk_adjustment,
            false_positive=first_finding.false_positive,
            operational_requirement=first_finding.operational_requirement,
            deviation_rationale=first_finding.deviation_rationale,
            supporting_documents=first_finding.supporting_documents,
            comments="", # No finding IDs for CIS findings
            auto_approve=first_finding.auto_approve,
            binding_operational_directive_22_01_tracking=first_finding.binding_operational_directive_22_01_tracking,
            binding_operational_directive_22_01_due_date=first_finding.binding_operational_directive_22_01_due_date,
            cve=first_finding.cve,
            service_name=first_finding.service_name  
        )
        
        result.append((findings_list, poam))
        
    return result 