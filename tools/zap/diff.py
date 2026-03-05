"""
Module for comparing ZAP findings against existing POAMs.
"""
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any, Union
from pathlib import Path
from datetime import datetime

from ..findings import Finding
from ..poam import PoamFile, PoamEntry
from ..diff import PoamFileDiff, compare_findings_to_poams
from .poam_generator import generate_poams_from_findings

@dataclass
class FindingPoamMatch:
    """Represents a match between a finding and an existing POAM."""
    finding: Finding
    poam: PoamEntry

@dataclass
class ZapAlertsDiff:
    """Represents the difference between current findings and existing POAMs."""
    new_findings: List[Finding]  # Findings without corresponding POAMs
    existing_matches: List[FindingPoamMatch]  # Findings matched to existing POAMs
    closed_poams: List[PoamEntry]  # POAMs without corresponding findings
    reopened_findings: List[FindingPoamMatch]  # Findings that match previously closed POAMs
    proposed_poams: List[Tuple[List[Finding], PoamEntry]]  # Proposed new POAMs with their findings

    def to_json(self) -> Dict[str, Any]:
        """
        Convert the diff results to a JSON-serializable dictionary.
        
        Returns:
            Dictionary containing the diff results in a structured format
        """
        def format_datetime(dt: Union[datetime, str]) -> str:
            if isinstance(dt, str):
                return dt
            else:
                return dt.strftime("%Y-%m-%d") if dt else None
            
        def poam_to_full_dict(poam: PoamEntry) -> Dict[str, Any]:
            """Convert a POAM to a complete dictionary with all fields."""
            return {
                "poam_id": poam.poam_id,
                "controls": poam.controls,
                "weakness_name": poam.weakness_name,
                "weakness_description": poam.weakness_description,
                "weakness_detector_source": poam.weakness_detector_source,
                "weakness_source_identifier": poam.weakness_source_identifier,
                "asset_identifier": poam.asset_identifier,
                "point_of_contact": poam.point_of_contact,
                "resources_required": poam.resources_required,
                "overall_remediation_plan": poam.overall_remediation_plan,
                "original_detection_date": format_datetime(poam.original_detection_date),
                "scheduled_completion_date": format_datetime(poam.scheduled_completion_date),
                "planned_milestones": poam.planned_milestones,
                "milestone_changes": poam.milestone_changes,
                "status_date": format_datetime(poam.status_date),
                "vendor_dependency": poam.vendor_dependency,
                "last_vendor_check_in_date": format_datetime(poam.last_vendor_check_in_date),
                "vendor_dependent_product_name": poam.vendor_dependent_product_name,
                "original_risk_rating": poam.original_risk_rating,
                "adjusted_risk_rating": poam.adjusted_risk_rating,
                "risk_adjustment": poam.risk_adjustment,
                "false_positive": poam.false_positive,
                "operational_requirement": poam.operational_requirement,
                "deviation_rationale": poam.deviation_rationale,
                "supporting_documents": poam.supporting_documents,
                "comments": poam.comments,
                "auto_approve": poam.auto_approve,
                "binding_operational_directive_22_01_tracking": poam.binding_operational_directive_22_01_tracking,
                "binding_operational_directive_22_01_due_date": format_datetime(poam.binding_operational_directive_22_01_due_date),
                "cve": poam.cve,
                "service_name": poam.service_name
            }
            
        def finding_to_dict(finding: Finding) -> Dict[str, Any]:
            return {
                "finding_id": finding.finding_id,
                "weakness_name": finding.weakness_name,
                "asset_identifier": finding.asset_identifier,
                "original_detection_date": format_datetime(finding.original_detection_date),
                "original_risk_rating": finding.original_risk_rating,
                "cve": finding.cve,
                "service_name": finding.service_name
            }
        
        return {
            "metadata": {
                "new_findings_count": len(self.new_findings),
                "existing_matches_count": len(self.existing_matches),
                "closed_poams_count": len(self.closed_poams),
                "reopened_findings_count": len(self.reopened_findings),
                "proposed_poams_count": len(self.proposed_poams)
            },
            "new_poams": [
                {
                    "poam": poam_to_full_dict(poam),
                    "findings": [finding_to_dict(f) for f in findings],
                    "finding_ids": [f.finding_id for f in findings]
                }
                for findings, poam in self.proposed_poams
            ],
            "reopen_poams": [
                {
                    "poam_id": match.poam.poam_id,
                    "finding_id": match.finding.finding_id
                }
                for match in self.reopened_findings
            ],
            "close_poams": [poam.poam_id for poam in self.closed_poams]
        }

    def print_summary(self, max_preview: int = 10) -> None:
        """Print a human-readable summary of the diff."""
        # Print new findings
        print("\n=== New Findings ===")
        print(f"Count: {len(self.new_findings)}")
        if self.new_findings:
            finding_ids = [finding.finding_id for finding in self.new_findings]
            print(f"Finding IDs: {', '.join(finding_ids)}")

        # Print existing matches
        print("\n=== Existing Matches ===")
        print(f"Count: {len(self.existing_matches)}")
        if self.existing_matches:
            matches = [f"{match.finding.finding_id} -> {match.poam.poam_id}" 
                      for match in self.existing_matches[:max_preview]]
            print(f"Preview of matches: {', '.join(matches)}")
            if len(self.existing_matches) > max_preview:
                print(f"... and {len(self.existing_matches) - max_preview} more")

        # Print reopened findings
        print("\n=== Reopened Findings ===")
        print(f"Count: {len(self.reopened_findings)}")
        if self.reopened_findings:
            matches = [f"{match.finding.finding_id} -> {match.poam.poam_id}" 
                      for match in self.reopened_findings[:max_preview]]
            print(f"Preview of matches: {', '.join(matches)}")
            if len(self.reopened_findings) > max_preview:
                print(f"... and {len(self.reopened_findings) - max_preview} more")

        # Print closed POAMs
        print("\n=== Closed POAMs ===")
        print(f"Count: {len(self.closed_poams)}")
        if self.closed_poams:
            poam_ids = [poam.poam_id for poam in self.closed_poams]
            print(f"POAM IDs no longer active: {', '.join(poam_ids)}")

        # Print proposed POAMs
        print("\n=== Proposed POAMs ===")
        print(f"Count: {len(self.proposed_poams)}")
        if self.proposed_poams:
            for findings, poam in self.proposed_poams[:max_preview]:
                finding_ids = [f.finding_id for f in findings]
                print(f"{', '.join(finding_ids)} => {poam.poam_id}")
            if len(self.proposed_poams) > max_preview:
                print(f"... and {len(self.proposed_poams) - max_preview} more")
            
            # Show sample of first proposed POAM
            print("\nSample new POAM:")
            sample_findings, sample_poam = self.proposed_poams[0]
            print(f"POAM ID: {sample_poam.poam_id}")
            print(f"Weakness Name: {sample_poam.weakness_name}")
            print(f"Asset Identifiers: {sample_poam.asset_identifier}")
            print(f"Finding IDs: {sample_poam.comments}")
            # Handle case where date might already be a string
            detection_date = sample_poam.original_detection_date
            if isinstance(detection_date, datetime):
                detection_date = detection_date.strftime('%Y-%m-%d')
            print(f"Detection Date: {detection_date}")
            print(f"Risk Rating: {sample_poam.original_risk_rating}")
            if sample_poam.cve:
                print(f"CVE: {sample_poam.cve}")

def _is_exact_match(str1: str, str2: str) -> bool:
    """Check if two strings match exactly, ignoring case."""
    if not str1 or not str2:
        return False
    return str1.lower().strip() == str2.lower().strip()

def _is_asset_covered(finding_asset: str, poam_assets: str) -> bool:
    """
    Check if the finding's asset is included in the POAM's asset list.
    
    Args:
        finding_asset: Asset identifier from the finding
        poam_assets: Asset identifier field from the POAM (may contain multiple assets)
        
    Returns:
        True if the finding's asset is contained within the POAM's asset list
    """
    if not finding_asset or not poam_assets:
        return False
    return finding_asset.lower().strip() in poam_assets.lower().strip()

def _find_matching_poam(finding: Finding, poams: List[PoamEntry]) -> Optional[FindingPoamMatch]:
    """Find a matching POAM for a given finding based on exact weakness name match and asset coverage."""
    for poam in poams:
        # Weakness name must match exactly, and the finding's asset must be included in the POAM's assets
        if (_is_exact_match(finding.weakness_name, poam.weakness_name) and 
            _is_asset_covered(finding.asset_identifier, poam.asset_identifier)):
            return FindingPoamMatch(finding=finding, poam=poam)
    
    return None

def get_zap_poam_entries(poam_file: PoamFile) -> Tuple[List[PoamEntry], List[PoamEntry]]:
    """
    Get ZAP POAMs from a POAM file.
    
    Args:
        poam_file: PoamFile instance
        
    Returns:
        Tuple of (open_poams, closed_poams)
    """
    # Pattern matches YYYY-ZAPXXXX where XXXX is 4 or more digits
    zap_pattern = r'^\d{4}-ZAP\d{4,}$'
    
    # Get open POAMs
    open_df = poam_file.df[poam_file.df['POAM ID'].str.match(zap_pattern, na=False)]
    open_poams = [PoamEntry.from_dict(row) for _, row in open_df.iterrows()]
    
    # Get closed POAMs if available
    closed_poams = []
    if poam_file.closed_df is not None:
        closed_df = poam_file.closed_df[poam_file.closed_df['POAM ID'].str.match(zap_pattern, na=False)]
        closed_poams = [PoamEntry.from_dict(row) for _, row in closed_df.iterrows()]
    
    return open_poams, closed_poams

def compare_findings_to_zap_poams(findings: List[Finding], poam_file: Path) -> PoamFileDiff:
    """
    Compare a list of findings against ZAP POAMs.
    
    Args:
        findings: List of current findings from ZAP
        poam_file: Path to Excel file containing ZAP POAMs
        
    Returns:
        PoamFileDiff containing new, existing, closed, and reopened findings
    """
    # Load ZAP POAMs
    poam_file_handler = PoamFile(poam_file)
    open_poams, closed_poams = get_zap_poam_entries(poam_file_handler)
    
    # Get all POAM IDs for generating new ones
    all_poam_ids = [p.poam_id for p in [*open_poams, *closed_poams]]
    
    return compare_findings_to_poams(findings, open_poams, closed_poams, all_poam_ids, generate_poams_from_findings, store_as_configuration_findings=False)
