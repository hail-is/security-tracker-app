"""
Module for comparing Trivy findings against existing POAMs.
"""
from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path

from ..findings import Finding
from ..poam import PoamFile, PoamEntry

@dataclass
class FindingPoamMatch:
    """Represents a match between a finding and an existing POAM."""
    finding: Finding
    poam: PoamEntry

@dataclass
class TrivyAlertsDiff:
    """Represents the difference between current findings and existing POAMs."""
    new_findings: List[Finding]  # Findings without corresponding POAMs
    existing_matches: List[FindingPoamMatch]  # Findings matched to existing POAMs
    closed_poams: List[PoamEntry]  # POAMs without corresponding findings

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

        # Print closed POAMs
        print("\n=== Closed POAMs ===")
        print(f"Count: {len(self.closed_poams)}")
        if self.closed_poams:
            poam_ids = [poam.poam_id for poam in self.closed_poams]
            print(f"POAM IDs no longer active: {', '.join(poam_ids)}")

def _is_exact_match(text1: str, text2: str) -> bool:
    """
    Check if two strings match exactly (case-insensitive).
    
    Args:
        text1: First text string
        text2: Second text string
        
    Returns:
        True if strings match exactly (ignoring case), False otherwise
    """
    if not text1 or not text2:
        return False
    return text1.lower().strip() == text2.lower().strip()

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


def compare_findings_to_trivy_poams(findings: List[Finding], poam_file: Path) -> TrivyAlertsDiff:
    """
    Compare a list of findings against Trivy POAMs.
    
    Args:
        findings: List of current findings from Trivy
        poam_file: Path to Excel file containing Trivy POAMs
        
    Returns:
        TrivyAlertsDiff containing new, existing, and closed findings
    """
    # Load Trivy POAMs
    poam_entries = PoamFile(poam_file).get_trivy_poam_entries()
    return compare_findings_to_poams(findings, poam_entries)


def compare_findings_to_poams(findings: List[Finding], poam_entries: List[PoamEntry]) -> TrivyAlertsDiff:
    """
    Compare a list of findings against existing POAMs.
    
    Args:
        findings: List of current findings from Trivy
        poam_file: Path to Excel file containing existing POAMs
        
    Returns:
        TrivyAlertsDiff containing new, existing, and closed findings
    """
    # Track which POAMs are matched
    matched_poams = set()
    new_findings = []
    existing_matches = []
    
    # Find matches for each finding
    for finding in findings:
        match = _find_matching_poam(finding, poam_entries)
        if match:
            existing_matches.append(match)
            matched_poams.add(match.poam)
        else:
            new_findings.append(finding)
    
    # Find closed POAMs (those without matches)
    closed_poams = [poam for poam in poam_entries if poam not in matched_poams]
    
    return TrivyAlertsDiff(
        new_findings=new_findings,
        existing_matches=existing_matches,
        closed_poams=closed_poams
    ) 