"""
Module for handling ZAP scan reports and converting alerts to findings.
"""
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
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

def parse_zap_xml(xml_file: str) -> List[Finding]:
    """
    Parse a ZAP XML report and extract alert findings.
    
    Args:
        xml_file: Path to the ZAP XML report file
        
    Returns:
        List of Finding objects
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    findings = []
    
    # Extract scan date from report
    scan_date = datetime.strptime(root.get('generated'), '%a, %d %b %Y %H:%M:%S')
    
    # Process each alert
    for site in root.findall('.//site'):
        for alertitem in site.findall('.//alertitem'):
            # Get basic alert info
            alert_name = alertitem.find('alert').text
            risk_code = int(alertitem.find('riskcode').text)
            description = alertitem.find('desc').text
            plugin_id = alertitem.find('pluginid').text
            
            # Map risk code to severity
            severity_map = {
                0: 'Informational',
                1: 'Low',
                2: 'Medium',
                3: 'High'
            }
            severity = severity_map.get(risk_code, 'Unknown')
            
            # Calculate completion date based on severity
            completion_date = get_completion_date(severity, scan_date)
            
            # Create a finding for each instance
            for idx, instance in enumerate(alertitem.findall('.//instance')):
                uri = instance.find('uri').text
                evidence = instance.find('evidence').text if instance.find('evidence') is not None else None
                other_info = instance.find('otherinfo').text if instance.find('otherinfo') is not None else None
                
                # Add evidence and other info to description if available
                full_description = description
                if evidence:
                    full_description += f"\n\nEvidence:\n{evidence}"
                if other_info:
                    full_description += f"\n\nAdditional Information:\n{other_info}"
                
                finding = Finding(
                    finding_id=f"ZAP-{plugin_id}-{idx+1}",
                    controls="RA-5",
                    weakness_name=alert_name,
                    weakness_description=full_description,
                    weakness_detector_source="ZAP",
                    weakness_source_identifier=plugin_id,
                    asset_identifier=uri,
                    point_of_contact="Chris Llanwarne",
                    resources_required="None",
                    overall_remediation_plan="Perform necessary updates to resolve the vulnerability",
                    original_detection_date=scan_date,
                    scheduled_completion_date=completion_date,
                    planned_milestones=f"(1) {completion_date.strftime('%Y-%m-%d')}: Perform necessary updates to resolve the vulnerability",
                    milestone_changes="",
                    status_date=scan_date,
                    vendor_dependency="No",
                    last_vendor_check_in_date=None,
                    vendor_dependent_product_name="N/A",
                    original_risk_rating=severity,
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

def convert_alerts_to_findings(xml_file: str) -> str:
    """
    Convert ZAP XML alerts to findings JSON format.
    
    Args:
        xml_file: Path to the ZAP XML report file
        
    Returns:
        Path to the output JSON file
    """
    findings = parse_zap_xml(xml_file)
    
    # Convert findings to dictionaries
    findings_data = []
    for finding in findings:
        finding_dict = vars(finding)
        # Convert datetime objects to strings
        for key, value in finding_dict.items():
            if isinstance(value, datetime):
                finding_dict[key] = value.strftime('%Y-%m-%d %H:%M:%S')
        findings_data.append(finding_dict)
    
    # Generate output filename
    input_path = Path(xml_file)
    output_file = input_path.with_suffix('.findings.json')
    
    # Write findings to JSON file
    with open(output_file, 'w') as f:
        json.dump(findings_data, f, indent=2)
    
    return str(output_file) 