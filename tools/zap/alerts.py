"""
Module for handling ZAP scan reports and converting alerts to findings.
"""
import csv
from datetime import datetime, timedelta, timezone
from typing import List
import json
from pathlib import Path
from ..findings import Finding

def get_completion_date(severity: str, detection_date: datetime) -> datetime:
    """Calculate completion date based on severity."""
    days_map = {
        'Critical': 15,
        'High': 30,
        'Medium': 90,  # Using 90 days for medium
        'Low': 180,
        'Informational': 180
    }
    days = days_map.get(severity, 180)  # Default to 180 days if unknown severity
    return detection_date + timedelta(days=days)

def parse_zap_csv(csv_file: str) -> List[Finding]:
    """
    Parse a ZAP CSV report and extract alert findings.
    
    Args:
        csv_file: Path to the ZAP CSV report file
        
    Returns:
        List of Finding objects
    """
    findings = []
    
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Parse dates
            detection_date = datetime.strptime(row['Original Detection Date'], '%m/%d/%Y')
            detection_date = detection_date.replace(tzinfo=timezone.utc)
            
            # Parse completion date if available
            completion_date = None
            if row['Scheduled Completion Date']:
                try:
                    completion_date = datetime.strptime(row['Scheduled Completion Date'], '%Y-%m-%d %H:%M:%S')
                    completion_date = completion_date.replace(tzinfo=timezone.utc)
                except ValueError:
                    # If parsing fails, calculate based on risk rating
                    completion_date = get_completion_date(row['Original Risk Rating'], detection_date)
            else:
                completion_date = get_completion_date(row['Original Risk Rating'], detection_date)
            
            # Create finding
            finding = Finding(
                finding_id=f"{row['ids']}",
                controls="RA-5",
                weakness_name=row['Weakness Name'],
                weakness_description=row['Weakness Description'],
                weakness_detector_source=row['Weakness Detector Source'],
                weakness_source_identifier=row['Weakness Source Identifier'],
                asset_identifier=row['Asset Identifier'],
                point_of_contact="Chris Llanwarne",
                resources_required="None",
                overall_remediation_plan="Perform necessary updates to resolve the vulnerability",
                original_detection_date=detection_date,
                scheduled_completion_date=completion_date,
                planned_milestones=f"(1) {completion_date.strftime('%Y-%m-%d')}: Perform necessary updates to resolve the vulnerability",
                milestone_changes="",
                status_date=datetime.now(timezone.utc),
                vendor_dependency="No",
                last_vendor_check_in_date=None,
                vendor_dependent_product_name="N/A",
                original_risk_rating=row['Original Risk Rating'],
                adjusted_risk_rating=None,
                risk_adjustment="",
                false_positive="",
                operational_requirement="",
                deviation_rationale=None,
                supporting_documents=None,
                comments=None,
                auto_approve="",
                binding_operational_directive_22_01_tracking="",
                binding_operational_directive_22_01_due_date=None,
                cve=None,
                service_name="Hail"
            )
            findings.append(finding)
    
    return findings

def convert_alerts_to_findings(csv_file: str, output_file: str = None) -> str:
    """
    Convert ZAP CSV alerts to findings JSON format.
    
    Args:
        csv_file: Path to the ZAP CSV report file
        output_file: Optional output file path. If None, uses input file with .findings.json extension
        
    Returns:
        Path to the output JSON file
    """
    findings = parse_zap_csv(csv_file)
    
    # Convert findings to dictionaries
    findings_data = []
    for finding in findings:
        finding_dict = vars(finding)
        # Convert datetime objects to strings
        for key, value in finding_dict.items():
            if isinstance(value, datetime):
                finding_dict[key] = value.strftime('%Y-%m-%d %H:%M:%S')
        findings_data.append(finding_dict)
    
    # Determine output filename
    if output_file is None:
        input_path = Path(csv_file)
        output_file = str(input_path.with_suffix('.findings.json'))
    
    # Write findings to JSON file
    with open(output_file, 'w') as f:
        json.dump(findings_data, f, indent=2)
    
    return output_file 