"""
Tool for importing Trivy alerts from CSV format into Finding objects.
"""
import csv
from datetime import datetime
from pathlib import Path
from typing import List

from ..findings import Finding

def parse_date(date_str: str) -> datetime:
    """Parse a date string in MM/DD/YY format into a datetime object."""
    try:
        return datetime.strptime(date_str, "%m/%d/%y")
    except ValueError as e:
        raise ValueError(f"Invalid date format (expected MM/DD/YY): {date_str}") from e

def import_alerts_from_csv(csv_file: Path) -> List[Finding]:
    """
    Import Trivy alerts from a CSV file and convert them to Finding objects.
    
    Args:
        csv_file: Path to the CSV file containing Trivy alerts
        
    Returns:
        List of Finding objects
    """
    entries = []
    
    with csv_file.open('r', newline='') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            # Convert CSV field names to Finding field names
            entry_data = {
                'finding_id': row['Alert ID'],
                'controls': row['Controls'],
                'weakness_name': row['Weakness Name'],
                'weakness_description': row['Weakness Description'],
                'weakness_detector_source': row['Weakness Detector Source'],
                'weakness_source_identifier': row['Weakness Source Identifier'],
                'asset_identifier': row['Asset Identifier'],
                'point_of_contact': row['Point of Contact'],
                'resources_required': row['Resources Required'] or None,
                'overall_remediation_plan': row['Overall Remediation Plan'],
                'original_detection_date': parse_date(row['Original Detection Date']),
                'scheduled_completion_date': parse_date(row['Scheduled Completion Date']),
                'planned_milestones': row['Planned Milestones'],
                'milestone_changes': row['Milestone Changes'],
                'status_date': parse_date(row['Status Date']),
                'vendor_dependency': row['Vendor Dependency'],
                'last_vendor_check_in_date': parse_date(row['Last Vendor Check-in Date']) if row['Last Vendor Check-in Date'] else None,
                'vendor_dependent_product_name': row['Vendor Dependent Product Name'],
                'original_risk_rating': row['Original Risk Rating'],
                'adjusted_risk_rating': row['Adjusted Risk Rating'] or None,
                'risk_adjustment': row['Risk Adjustment'],
                'false_positive': row['False Positive'],
                'operational_requirement': row['Operational Requirement'],
                'deviation_rationale': row['Deviation Rationale'] or None,
                'supporting_documents': row['Supporting Documents'] or None,
                'comments': row['Comments'] or None,
                'auto_approve': row['Auto-Approve'],
                'binding_operational_directive_22_01_tracking': row['Binding Operational Directive 22-01 tracking'],
                'binding_operational_directive_22_01_due_date': parse_date(row['Binding Operational Directive 22-01 Due Date']) if row['Binding Operational Directive 22-01 Due Date'] else None,
                'cve': row['CVE'] or None,
                'service_name': row['Service Name']
            }
            
            entries.append(Finding(**entry_data))
    
    return entries 