"""
Tool for converting Trivy alerts to POAM format.
"""
import csv
import json
from datetime import datetime, timedelta
from pathlib import Path
import jq

from ..utils import ensure_working_dir

# JQ query to transform GitHub alerts into POAM format
ALERTS_TO_POAM_QUERY = """
.[] | { 
    "_state": .state,
    "Alert ID": .number, 
    "Controls": "RA-5",
    "Weakness Name": (.rule.description + "; " + .rule.id),
    "Weakness Description": .rule.full_description,
    "Weakness Detector Source": .html_url,
    "Weakness Source Identifier": (.tool.name + " " + .tool.version),
    "Asset Identifier": .rule.most_recent_instance.location.path,
    "Point of Contact": "Chris Llanwarne",
    "Resources Required": "None",
    "Overall Remediation Plan": "Perform necessary updates to resolve the vulnerability",
    "Original Detection Date": .created_at,
    "Status Date": .updated_at,
    "Last Vendor Check-in Date": .rule.updated_at,
    "Scheduled Completion Date": "DATE",
    "AGENCY Scheduled Completion Date": "DATE",
    "Planned Milestones": "DATE: Perform necessary updates to resolve the vulnerability",
    "Milestone Changes": "",
    "Vendor Dependency": "Yes",
    "Vendor Dependent Product Name": "Ubuntu",
    "Original Risk Rating": .rule.security_severity_level,
    "Adjusted Risk Rating": "",
    "Risk Adjustment": "",
    "False Positive": "No",
    "Operational Requirement": "No",
    "Deviation Rationale": "",
    "Supporting Documents": "",
    "Comments": .most_recent_instance.message.text,
    "Auto-Approve": "No",
    "Binding Operational Directive 22-01 tracking": "",
    "Binding Operational Directive 22-01 Due Date": "",
    "CVE": .rule.id,
    "Service Name": "Hail Batch"
}"""

# POAM CSV field names in order
FIELDNAMES = [
    "Alert ID", "Controls", "Weakness Name", "Weakness Description",
    "Weakness Detector Source", "Weakness Source Identifier", "Asset Identifier",
    "Point of Contact", "Resources Required", "Overall Remediation Plan",
    "Original Detection Date", "Scheduled Completion Date",
    "AGENCY Scheduled Completion Date", "Planned Milestones", "Milestone Changes",
    "Status Date", "Vendor Dependency", "Last Vendor Check-in Date",
    "Vendor Dependent Product Name", "Original Risk Rating", "Adjusted Risk Rating",
    "Risk Adjustment", "False Positive", "Operational Requirement",
    "Deviation Rationale", "Supporting Documents", "Comments", "Auto-Approve",
    "Binding Operational Directive 22-01 tracking",
    "Binding Operational Directive 22-01 Due Date", "CVE", "Service Name"
]

def date_plus(iso_date_string: str, days_to_add: int) -> str:
    """
    Parses an ISO date string, adds days, and formats it to MM/DD/YY.
    
    Args:
        iso_date_string: The ISO date string to parse (e.g., "2023-10-26T12:00:00Z")
        days_to_add: The number of days to add (can be positive or negative)
    
    Returns:
        The formatted date string (MM/DD/YY), or None if parsing fails
    """
    try:
        date_object = datetime.fromisoformat(iso_date_string.replace("Z", "+00:00"))
        modified_date = date_object + timedelta(days=days_to_add)
        return modified_date.strftime("%m/%d/%y")
    except ValueError as e:
        raise ValueError(f"Invalid ISO date string format: {iso_date_string}") from e

def convert_alerts_to_poam(alerts_file: Path, output_path: Path = None) -> Path:
    """
    Convert GitHub Trivy alerts JSON to POAM CSV format.
    
    Args:
        alerts_file: Path to the JSON file containing GitHub alerts
        output_path: Optional path for the output file. If None, uses same parent directory as input file.
        
    Returns:
        Path to the generated CSV file
    """
    # Load alerts data
    alerts_data = json.loads(alerts_file.read_text())
    
    # Compile and run JQ query
    alerts_jq = jq.compile(ALERTS_TO_POAM_QUERY)
    jq_results = alerts_jq.input_value(alerts_data)
    rows: list[dict] = []
    
    # Process each alert
    for row in jq_results.all():
        # Skip non-Trivy and closed alerts
        if row["Weakness Source Identifier"][:5] != "Trivy" or row.pop("_state") != "open":
            continue
            
        # Parse message for asset information
        message = {
            kv[0]: (kv[1] if len(kv) > 1 else "")
            for kv in [line.split(": ") for line in row["Comments"].split("\n")]
        }
        
        if "Image" not in message or "Package" not in message:
            continue
            
        # Update asset identifier
        row["Asset Identifier"] = f"{message['Image']} ({message['Package']})"
        
        # Handle dates and intervals
        orig_date = row["Original Detection Date"]
        status_date = row["Status Date"]
        sev = row["Original Risk Rating"].lower()
        
        # Calculate fix date based on severity
        fix_intervals = {"high": 14, "medium": 90, "low": 180}
        fix_interval = fix_intervals.get(sev, 0)
        fix_date = date_plus(orig_date, fix_interval)
        
        # Update all dates
        row["Original Detection Date"] = date_plus(orig_date, 0)
        row["Status Date"] = date_plus(status_date, 0)
        row["Last Vendor Check-in Date"] = date_plus(status_date, 0)
        row["Scheduled Completion Date"] = fix_date
        row["AGENCY Scheduled Completion Date"] = fix_date
        row["Planned Milestones"] = row["Planned Milestones"].replace("DATE", fix_date)
        
        rows.append(row)
    
    # Determine output file path
    if output_path is None:
        # Use same parent directory as input file, change extension to .findings.csv
        output_file = alerts_file.parent / f"{alerts_file.stem}.findings.csv"
    else:
        output_file = output_path
    
    # Write CSV file
    with output_file.open('w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    
    return output_file 