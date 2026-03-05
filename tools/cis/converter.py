"""
Module for converting CIS scan reports to findings.
"""
from pathlib import Path
import pandas as pd
from datetime import datetime, timedelta
from typing import List
import json

from ..findings import Finding

def get_cvss_range(cvss: str) -> str:
    """Convert CVSS score to range category."""
    try:
        score = float(cvss)
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0:
            return "Low"
        else:
            return "Info"
    except (ValueError, TypeError):
        if not cvss:
            return "Info"
        else:
            return "Unknown"

def calculate_due_date(cvss: str, detection_date: datetime) -> datetime:
    """Calculate due date based on severity level."""
    severity_mapping = {
        'Critical': 15,
        'High': 30,
        'Medium': 90,
        'Low': 180,
        'Info': 180
    }
    severity = get_cvss_range(cvss)
    days = severity_mapping.get(severity, 180)  # Default to 180 days for unknown
    return detection_date + timedelta(days=days)

def convert_csv_to_findings(input_file: Path) -> List[Finding]:
    """
    Convert a CIS CSV file to a list of findings.
    
    Args:
        input_file: Path to the input CSV file
        
    Returns:
        List of Finding objects
    """
    # Read the CSV file
    df = pd.read_csv(input_file)
    
    # Extract date from filename
    date_str = input_file.stem.split(" - ")[-1]
    detection_date = datetime.strptime(date_str, "%Y-%m-%d")
    
    findings = []
    
    # Process each row
    for _, row in df.iterrows():
        # Split failures into individual asset identifiers
        failures = row['Failures'].strip().split('\n')
        
        # Calculate completion date based on CVSS
        completion_date = calculate_due_date(row['CVSS'], detection_date)
        
        # Create a finding for each failure
        for failure in failures:
            finding = Finding(
                finding_id=f"CIS-{row['CIS_ID']}-{len(findings)+1:04d}",
                controls="CM-6",
                weakness_name=row['Title'],
                weakness_description=row['Description'],
                weakness_detector_source=input_file.name,
                weakness_source_identifier="CIS",
                asset_identifier=failure.strip(),
                point_of_contact="Chris Llanwarne",
                resources_required=None,
                overall_remediation_plan="Perform necessary updates to resolve the vulnerability",
                original_detection_date=detection_date,
                scheduled_completion_date=completion_date,
                planned_milestones=f"(1) {completion_date.strftime('%Y-%m-%d')} Perform necessary updates to resolve the vulnerability",
                milestone_changes="",
                status_date=detection_date,
                vendor_dependency="No",
                last_vendor_check_in_date=None,
                vendor_dependent_product_name="",
                original_risk_rating=get_cvss_range(row['CVSS']),
                adjusted_risk_rating="N/A",
                risk_adjustment="",
                false_positive="No",
                operational_requirement="No",
                deviation_rationale=None,
                supporting_documents=None,
                comments=None,
                auto_approve="No",
                binding_operational_directive_22_01_tracking="",
                binding_operational_directive_22_01_due_date=None,
                cve=None,
                service_name="Hail"
            )
            findings.append(finding)
    
    return findings

def convert_to_findings_file(input_file: Path, output_file: Path = None) -> Path:
    """
    Convert a CIS CSV file to a findings JSON file.
    
    Args:
        input_file: Path to the input CSV file
        output_file: Optional output file path. If None, uses input file with .findings.json extension
        
    Returns:
        Path to the output JSON file
    """
    # Generate findings
    findings = convert_csv_to_findings(input_file)
    
    # Convert findings to dictionaries
    findings_data = []
    for finding in findings:
        finding_dict = vars(finding)
        # Convert datetime objects to strings
        for key, value in finding_dict.items():
            if isinstance(value, datetime):
                finding_dict[key] = value.strftime("%Y-%m-%d")
        findings_data.append(finding_dict)
    
    # Determine output file path
    if output_file is None:
        output_file = input_file.with_suffix('.findings.json')
    
    # Write to JSON file
    with open(output_file, 'w') as f:
        json.dump(findings_data, f, indent=2)
    
    return output_file 