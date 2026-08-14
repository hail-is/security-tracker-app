"""
Module for comparing findings against existing POAMs.
"""
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any, Union
from pathlib import Path
from datetime import datetime

from .findings import Finding
from .poam import PoamFile, PoamEntry

@dataclass
class FindingPoamMatch:
    """Represents a match between a finding and an existing POAM."""
    finding: Finding
    poam: PoamEntry

@dataclass
class PoamFileDiff:
    """Represents the difference between current findings and existing POAMs."""
    new_findings: List[Finding]  # Findings without corresponding POAMs
    existing_matches: List[FindingPoamMatch]  # Findings matched to existing POAMs
    closed_poams: List[PoamEntry]  # POAMs without corresponding findings
    reopened_findings: List[FindingPoamMatch]  # Findings that match previously closed POAMs
    proposed_poams: List[Tuple[List[Finding], PoamEntry]]  # Proposed new POAMs with their findings
    proposed_configuration_findings: List[Tuple[List[Finding], PoamEntry]] # Proposed new configuration findings
    closed_configuration_findings: List[PoamEntry] # Configuration findings without matches

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
        
        result = {
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

        # Add configuration findings if present
        if self.proposed_configuration_findings is not None:
            result["metadata"]["proposed_configuration_findings_count"] = len(self.proposed_configuration_findings)
            result["proposed_configuration_findings"] = [
                {
                    "poam": poam_to_full_dict(poam),
                    "findings": [finding_to_dict(f) for f in findings],
                    "finding_ids": [f.finding_id for f in findings]
                }
                for findings, poam in self.proposed_configuration_findings
            ]
            
        if self.closed_configuration_findings is not None:
            result["metadata"]["closed_configuration_findings_count"] = len(self.closed_configuration_findings)
            result["closed_configuration_findings"] = [poam.poam_id for poam in self.closed_configuration_findings]

        return result

    def print_summary(self, max_preview: int = 10) -> None:
        """Print a human-readable summary of the diff.

        Categories that don't represent newly (re)opened items are shown as
        compact counts. Opened and reopened items get a scannable bulleted
        list since those are what typically need reviewing.
        """
        def format_date(date: Union[datetime, str, None]) -> str:
            if isinstance(date, datetime):
                return date.strftime('%Y-%m-%d')
            return date or "unknown date"

        print("\n=== Summary ===")
        print(f"New findings (unmatched, pre-grouping): {len(self.new_findings)}")
        print(f"Existing matches (no change): {len(self.existing_matches)}")
        print(f"Closed POAMs: {len(self.closed_poams)}")
        print(f"Closed configuration findings: {len(self.closed_configuration_findings)}")

        print("\n=== Opened POAMs ({}) ===".format(len(self.proposed_poams)))
        if self.proposed_poams:
            for findings, poam in self.proposed_poams[:max_preview]:
                finding_ids = ', '.join(f.finding_id for f in findings)
                date = format_date(poam.original_detection_date)
                print(f"- [{poam.poam_id}] {poam.weakness_name} "
                      f"({poam.original_risk_rating}, {date}) — {finding_ids}")
            if len(self.proposed_poams) > max_preview:
                print(f"  ... and {len(self.proposed_poams) - max_preview} more")

        print("\n=== Opened Configuration Findings ({}) ===".format(len(self.proposed_configuration_findings)))
        if self.proposed_configuration_findings:
            for findings, poam in self.proposed_configuration_findings[:max_preview]:
                finding_ids = ', '.join(f.finding_id for f in findings)
                date = format_date(poam.original_detection_date)
                print(f"- [{poam.poam_id}] {poam.weakness_name} "
                      f"({poam.original_risk_rating}, {date}) — {finding_ids}")
            if len(self.proposed_configuration_findings) > max_preview:
                print(f"  ... and {len(self.proposed_configuration_findings) - max_preview} more")

        print("\n=== Reopened Findings ({}) ===".format(len(self.reopened_findings)))
        if self.reopened_findings:
            for match in self.reopened_findings[:max_preview]:
                print(f"- [{match.poam.poam_id}] {match.poam.weakness_name} — {match.finding.finding_id}")
            if len(self.reopened_findings) > max_preview:
                print(f"  ... and {len(self.reopened_findings) - max_preview} more")

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
    """
    Find a matching POAM for a given finding.
    
    Args:
        finding: Finding to match
        poams: List of POAMs to search
        
    Returns:
        FindingPoamMatch if a match is found, None otherwise
    """
    for poam in poams:
        # Match based on exact weakness name match and asset coverage
        if _is_exact_match(finding.weakness_name, poam.weakness_name) and \
           _is_asset_covered(finding.asset_identifier, poam.asset_identifier):
            return FindingPoamMatch(finding=finding, poam=poam)
    return None

def compare_findings_to_poams(findings: List[Finding], 
                            open_poams: List[PoamEntry], 
                            closed_poams: List[PoamEntry],
                            existing_poam_ids: List[str],
                            poam_generator,
                            store_as_configuration_findings: bool = False) -> PoamFileDiff:
    """
    Compare a list of findings against existing POAMs.
    
    Args:
        findings: List of current findings
        open_poams: List of open POAMs
        closed_poams: List of closed POAMs
        existing_poam_ids: List of all existing POAM IDs
        poam_generator: Function to generate POAMs from findings
        store_as_configuration_findings: Whether to store results in configuration findings fields
        
    Returns:
        PoamFileDiff containing new, existing, closed, and reopened findings
    """
    # Track which POAMs are matched
    matched_poams = set()
    new_findings = []
    existing_matches = []
    reopened_findings = []
    
    # First check for matches against open POAMs
    for finding in findings:
        match = _find_matching_poam(finding, open_poams)
        if match:
            existing_matches.append(match)
            matched_poams.add(match.poam)
        else:
            # If no match in open POAMs, check closed POAMs
            closed_match = _find_matching_poam(finding, closed_poams)
            if closed_match:
                reopened_findings.append(closed_match)
            else:
                new_findings.append(finding)
    
    # Find closed POAMs (those without matches)
    closed_poams = [poam for poam in open_poams if poam not in matched_poams]
    
    # Generate proposed POAMs for new findings
    proposed_poams = poam_generator(new_findings, existing_poam_ids)
    
    return PoamFileDiff(
        new_findings=new_findings,
        existing_matches=existing_matches,
        closed_poams=closed_poams if not store_as_configuration_findings else [],
        reopened_findings=reopened_findings,
        proposed_poams=proposed_poams if not store_as_configuration_findings else [],
        proposed_configuration_findings=proposed_poams if store_as_configuration_findings else [],
        closed_configuration_findings=closed_poams if store_as_configuration_findings else []
    )
