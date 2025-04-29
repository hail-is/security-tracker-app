import pandas as pd
from datetime import datetime
from app.database.schema import get_db_connection, get_poam_config
from app.components.data_processor import get_cvss_range

def get_poam_id(created_at, issue_id):
    """Generate a POAM ID in the format YYYY-CISxxxx."""
    year = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S').year
    return f"{year}-CIS{issue_id:04d}"

def get_weakness_detector_source(scan_date):
    """Generate the weakness detector source string."""
    return f"Hail CIS GCP/GKE Compliance (rolling). Scan on {scan_date}"

def get_asset_identifier(google_project, findings):
    """Generate the asset identifier string."""
    return f"[{google_project}]: {findings}"

def get_planned_milestones(due_date):
    """Generate the planned milestones string."""
    return f"(1) {due_date}: Perform required updates to affected assets to remediate this finding."

def get_issue_findings(conn, issue_id):
    """Get all findings associated with an issue."""
    cursor = conn.cursor()
    cursor.execute('''
    SELECT DISTINCT f.failure
    FROM findings f
    JOIN remediation_findings rf ON f.id = rf.finding_id
    JOIN issue_remediations ir ON rf.remediation_id = ir.remediation_id
    WHERE ir.issue_id = ?
    ''', (issue_id,))
    return [row['failure'] for row in cursor.fetchall()]

def get_first_scan_date(conn, issue_id):
    """Get the first scan date for an issue."""
    cursor = conn.cursor()
    cursor.execute('''
    SELECT MIN(s.scan_date) as first_scan_date
    FROM scans s
    JOIN remediations r ON s.id = r.first_seen_scan
    JOIN issue_remediations ir ON r.id = ir.remediation_id
    WHERE ir.issue_id = ?
    ''', (issue_id,))
    result = cursor.fetchone()
    return result['first_scan_date'] if result else None

def generate_poam_export(status='open'):
    """Generate a POAM export for issues with the specified status."""
    conn = get_db_connection()
    config = get_poam_config(conn)
    
    if not config:
        raise ValueError("POAM configuration not found. Please configure POAM export settings first.")
    
    # Get issues with the specified status
    cursor = conn.cursor()
    cursor.execute('''
    SELECT 
        i.id,
        i.created_at,
        i.due_date,
        i.status,
        b.title,
        b.description,
        b.cvss
    FROM issues i
    JOIN benchmark b ON i.benchmark_id = b.id
    WHERE i.status = ?
    ORDER BY i.created_at ASC
    ''', (status,))
    
    issues = cursor.fetchall()
    
    # Prepare data for export
    export_data = []
    for issue in issues:
        findings = get_issue_findings(conn, issue['id'])
        findings_str = "\n".join(findings)
        first_scan_date = get_first_scan_date(conn, issue['id'])
        
        export_data.append({
            'POAM ID': get_poam_id(issue['created_at'], issue['id']),
            'Controls': 'CM-6',
            'Weakness Name': issue['title'],
            'Weakness Description': issue['description'],
            'Weakness Detector Source': get_weakness_detector_source(first_scan_date),
            'Weakness Source Identifier': 'CIS',
            'Asset Identifier': get_asset_identifier(config['google_project'], findings_str),
            'Point of Contact': config['point_of_contact'],
            'Resources Required': 'None',
            'Overall Remediation Plan': 'Perform necessary updates to resolve the vulnerability',
            'Original Detection Date': issue['created_at'],
            'Scheduled Completion Date': issue['due_date'],
            'AGENCY Scheduled Completion Date': issue['due_date'],
            'Planned Milestones': get_planned_milestones(issue['due_date']),
            'Milestone Changes': '',
            'Status Date': datetime.now().strftime('%Y-%m-%d'),
            'Vendor Dependency': 'No',
            'Last Vendor Check-in date': '',
            'Vendor Dependent Product Name': '',
            'Original Risk Rating': get_cvss_range(issue['cvss']),
            'Adjusted Risk Rating': 'N/A',
            'Risk Adjustment': 'No',
            'False Positive': 'No',
            'Operational Requirement': 'No',
            'Deviation Rationale': '',
            'Supporting Documents': '',
            'Comments': '',
            'Auto-Approve': 'No',
            'Binding Operational Directive 22-01 tracking': 'No',
            'Binding Operational Directive 22-01 Due Date': '',
            'CVE': '',
            'Service Name': config['service_name']
        })
    
    conn.close()
    return pd.DataFrame(export_data) 