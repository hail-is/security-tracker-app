"""
Module for comparing CIS findings against existing configuration findings.
"""
from pathlib import Path
from typing import List, Tuple
import pandas as pd
import re

from ..findings import Finding
from ..poam import PoamFile, PoamEntry
from ..diff import PoamFileDiff, compare_findings_to_poams
from .poam_generator import generate_poams_from_findings

def get_cis_configuration_findings(poam_file: PoamFile) -> List[PoamEntry]:
    """
    Get CIS configuration findings from a POAM file.
    
    Args:
        poam_file: PoamFile instance
        
    Returns:
        List of configuration findings from the Configuration Findings sheet
    """
    # Pattern matches YYYY-CISXXXX where XXXX is 4 or more digits
    cis_pattern = r'^\d{4}-CIS\d{4,}$'
    
    # Get configuration findings from the Configuration Findings sheet
    config_df = poam_file.workbook.parse(
        sheet_name="Configuration Findings",
        header=4  # 0-based index for row 5
    )
    config_findings = [
        PoamEntry.from_dict(row) 
        for _, row in config_df.iterrows() 
        if pd.notna(row.get('POAM ID')) and re.match(cis_pattern, str(row['POAM ID']))
    ]
    
    return config_findings

def compare_findings_to_cis_poams(findings: List[Finding], poam_file: Path) -> PoamFileDiff:
    """
    Compare a list of findings against CIS configuration findings.
    
    Args:
        findings: List of current findings from CIS
        poam_file: Path to Excel file containing CIS configuration findings
        
    Returns:
        PoamFileDiff containing new, existing, and closed configuration findings
    """
    # Load CIS configuration findings
    poam_file_handler = PoamFile(poam_file)
    config_findings = get_cis_configuration_findings(poam_file_handler)
    
    # Get all POAM IDs for generating new ones
    all_poam_ids = [p.poam_id for p in config_findings]
    
    # Compare findings using shared function, with empty closed_poams list and store as configuration findings
    return compare_findings_to_poams(
        findings=findings,
        open_poams=config_findings,
        closed_poams=[],  # No closed POAMs for CIS
        existing_poam_ids=all_poam_ids,
        poam_generator=generate_poams_from_findings,
        store_as_configuration_findings=True
    ) 
