"""
Module for generating POAMs from CIS findings.
"""
from datetime import datetime, timedelta
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
        current_year = datetime.now().year
        
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

def _group_findings_by_weakness(findings: List[Finding]) -> Dict[str, List[Finding]]:
    """
    Group findings by weakness name and asset identifier.
    
    Args:
        findings: List of findings to group
        
    Returns:
        Dictionary mapping (weakness_name, asset_identifier) to list of findings
    """
    groups = defaultdict(list)
    for finding in findings:
        key = (finding.weakness_name, finding.asset_identifier)
        groups[key].append(finding)
    return dict(groups)

def _get_completion_date(risk_rating: str) -> datetime:
    """
    Calculate completion date based on risk rating.
    
    Args:
        risk_rating: Risk rating of the finding
        
    Returns:
        Datetime object for completion date
    """
    today = datetime.now()
    
    if risk_rating.lower() == "critical":
        return today + timedelta(days=15)
    elif risk_rating.lower() == "high":
        return today + timedelta(days=30)
    elif risk_rating.lower() == "moderate":
        return today + timedelta(days=90)
    else:  # Low
        return today + timedelta(days=180)

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
    
    # Group findings by weakness name and asset
    grouped_findings = _group_findings_by_weakness(findings)
    
    for (weakness_name, asset_id), group in grouped_findings.items():
        # Get earliest detection date from group
        detection_date = min(f.original_detection_date for f in group)
        
        # Get highest risk rating from group
        risk_rating = max(f.original_risk_rating for f in group)
        
        # Generate POAM ID
        poam_id = _get_next_poam_id(existing_poam_ids, current_year)
        existing_poam_ids.append(poam_id)  # Add to list so next ID will be different
        
        # Get completion date based on risk
        completion_date = _get_completion_date(risk_rating)
        
        # Create POAM entry
        poam = PoamEntry(
            poam_id=poam_id,
            controls="",  # CIS findings don't map to specific controls
            weakness_name=weakness_name,
            weakness_description=f"CIS configuration finding: {weakness_name}",
            weakness_detector_source="CIS",
            weakness_source_identifier="",  # No specific identifier for CIS findings
            asset_identifier=asset_id,
            point_of_contact="Security Team",
            resources_required="Security Team time",
            overall_remediation_plan=f"Remediate {weakness_name} configuration finding",
            original_detection_date=detection_date,
            scheduled_completion_date=completion_date,
            planned_milestones="",
            milestone_changes="",
            status_date=datetime.now(),
            vendor_dependency="No",
            last_vendor_check_in_date=None,
            vendor_dependent_product_name="",
            original_risk_rating=risk_rating,
            adjusted_risk_rating="",
            risk_adjustment="",
            false_positive="No",
            operational_requirement="No",
            deviation_rationale="",
            supporting_documents="",
            comments=", ".join(f.finding_id for f in group),  # Store finding IDs in comments
            auto_approve="No",
            binding_operational_directive_22_01_tracking="No",
            binding_operational_directive_22_01_due_date=None,
            cve="",  # CIS findings don't have CVEs
            service_name=""  # CIS findings don't have service names
        )
        
        result.append((group, poam))
        
    return result 