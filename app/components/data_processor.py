import pandas as pd
from datetime import datetime, timedelta
from app.database.schema import (
    get_db_connection,
    get_or_create_benchmark,
    get_or_create_scan,
    insert_finding,
    create_remediation,
    link_finding_to_remediation,
    mark_remediations_resolved_if_not_in_list,
    get_active_remediations,
    get_resolved_remediations,
    create_issue_for_remediations
)

def get_cvss_range(cvss):
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
        return "Unknown"


def calculate_due_date(cvss, analysis_date):
    """Calculate due date based on severity level."""
    severity_mapping = {
        'Critical': 15,
        'High': 30,
        'Medium': 90,
        'Low': 180,
        'Info': 180
    }

    time_to_resolve = severity_mapping.get(get_cvss_range(cvss), 180)

    return datetime.strptime(analysis_date, '%Y-%m-%d 00:00:00') + timedelta(days=time_to_resolve)


def process_csv_upload(file, analysis_date):
    """Process uploaded CSV file and update database."""
    # Read CSV file
    df = pd.read_csv(file)
    required_columns = [
        'benchmark', 'id', 'level', 'cvss', 'title',
        'failures', 'description', 'rationale', 'refs'
    ]
    
    # Validate columns
    if not all(col in df.columns for col in required_columns):
        missing_cols = [col for col in required_columns if col not in df.columns]
        raise ValueError(f"Missing required columns: {', '.join(missing_cols)}")
    
    conn = get_db_connection()
    active_finding_ids = set()
    new_count = 0
    existing_count = 0
    
    try:
        # Get or create scan record
        scan_id = get_or_create_scan(conn, analysis_date)
        
        still_active_remediation_ids = []
        remediations_needing_issues = {}
        
        # Process each row
        for _, row in df.iterrows():
            # Create benchmark record
            benchmark_data = (
                row['benchmark'],
                row['id'],  # This is the finding_id from CSV
                row['level'],
                float(row['cvss']) if row['cvss'] else None,
                row['title'],
                row['description'],
                row['rationale'],
                row['refs']
            )
            benchmark_id = get_or_create_benchmark(conn, benchmark_data)
            
            # Handle multiple failures
            failures = str(row['failures']).split('\n')
            for failure in failures:
                failure = failure.strip()
                if not failure:
                    continue
                
                # Insert finding
                finding_id = insert_finding(conn, benchmark_id, failure)
                active_finding_ids.add(finding_id)
                
                # Check if finding is already part of an open remediation
                cursor = conn.cursor()
                cursor.execute('''
                SELECT r.id 
                FROM remediations r
                JOIN remediation_findings rf ON r.id = rf.remediation_id
                WHERE r.benchmark_id = ? 
                AND r.state = 'open'
                AND rf.finding_id = ?
                ''', (benchmark_id, finding_id))
                
                existing_remediation = cursor.fetchone()
                
                if existing_remediation:
                    still_active_remediation_ids.append(existing_remediation[0])
                    existing_count += 1
                else:
                    # Create new remediation
                    due_date = calculate_due_date(row['cvss'], analysis_date)
                    remediation_id = create_remediation(conn, benchmark_id, scan_id, due_date)
                    link_finding_to_remediation(conn, remediation_id, finding_id)
                    
                    # Get the list of remediation ids for the given benchmark and due date:
                    old_list = remediations_needing_issues.get((benchmark_id, due_date), [])
                    remediations_needing_issues[(benchmark_id, due_date)] = old_list.append(remediation_id)
                    new_count += 1

        for (benchmark_id, due_date), remediation_ids in remediations_needing_issues.items():
            create_issue_for_remediations(conn, remediation_ids, benchmark_id, due_date)
        
        # Mark findings as resolved if they're not in current upload
        # TODO: we should mark previously active resolutions as resolved if there is no new resolution matching the same finding
        mark_remediations_resolved_if_not_in_list(conn, scan_id, still_active_remediation_ids)
        
        # Get count of resolved findings in this scan
        cursor = conn.cursor()
        cursor.execute('''
        SELECT COUNT(*) as count 
        FROM remediations 
        WHERE resolved_in_scan = ?
        ''', (scan_id,))
        resolved_count = cursor.fetchone()['count']
        
        conn.commit()
        return {
            'new': new_count,
            'existing': existing_count,
            'resolved': resolved_count
        }
        
    finally:
        conn.close()

def get_findings_summary():
    """Get summary of findings for display."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        today = datetime.now().date()
        
        # Get active findings count
        cursor.execute('''
        SELECT COUNT(DISTINCT r.id) as count 
        FROM remediations r
        WHERE r.state = 'open'
        ''')
        active_count = cursor.fetchone()['count']
        
        # Get resolved findings count
        cursor.execute('''
        SELECT COUNT(DISTINCT r.id) as count 
        FROM remediations r
        WHERE r.state = 'resolved'
        ''')
        resolved_count = cursor.fetchone()['count']
        
        # Get findings by severity
        cursor.execute('''
        SELECT b.level, COUNT(DISTINCT r.id) as count
        FROM remediations r
        JOIN benchmark b ON r.benchmark_id = b.id
        WHERE r.state = 'open'
        GROUP BY b.level
        ''')
        severity_counts = {row['level']: row['count'] for row in cursor.fetchall()}
        
        # Get findings by CVSS
        cursor.execute('''
        SELECT b.cvss
        FROM remediations r
        JOIN benchmark b ON r.benchmark_id = b.id
        WHERE r.state = 'open'
        ''')
        cvss_scores = [row['cvss'] for row in cursor.fetchall()]
        cvss_ranges = [get_cvss_range(score) for score in cvss_scores]
        cvss_counts = pd.Series(cvss_ranges).value_counts().to_dict()
        
        # Get findings due within 28 days
        today_str = today.strftime('%Y-%m-%d')
        twenty_eight_days = (today + timedelta(days=28)).strftime('%Y-%m-%d')
        cursor.execute('''
        SELECT COUNT(DISTINCT r.id) as count
        FROM remediations r
        WHERE r.state = 'open'
        AND r.due_date <= ?
        AND r.due_date > ?
        ''', (twenty_eight_days, today_str))
        due_within_28_days = cursor.fetchone()['count']
        
        # Get findings due this week
        week_end = (today + timedelta(days=7)).strftime('%Y-%m-%d')
        cursor.execute('''
        SELECT COUNT(DISTINCT r.id) as count
        FROM remediations r
        WHERE r.state = 'open'
        AND r.due_date <= ?
        AND r.due_date > ?
        ''', (week_end, today_str))
        due_this_week = cursor.fetchone()['count']
        
        # Get overdue findings
        cursor.execute('''
        SELECT COUNT(DISTINCT r.id) as count
        FROM remediations r
        WHERE r.state = 'open'
        AND r.due_date < ?
        ''', (today_str,))
        overdue_count = cursor.fetchone()['count']
        
        # Get findings due after 28 days
        cursor.execute('''
        SELECT COUNT(DISTINCT r.id) as count
        FROM remediations r
        WHERE r.state = 'open'
        AND r.due_date > ?
        ''', (twenty_eight_days,))
        due_after_28_days = cursor.fetchone()['count']
        
        return {
            'active_count': active_count,
            'resolved_count': resolved_count,
            'severity_counts': severity_counts,
            'cvss_counts': cvss_counts,
            'due_within_28_days': due_within_28_days,
            'due_this_week': due_this_week,
            'overdue_count': overdue_count,
            'due_after_28_days': due_after_28_days
        }
        
    finally:
        conn.close()

def export_findings_to_df(status='active'):
    """Export findings to pandas DataFrame."""
    conn = get_db_connection()
    try:
        if status == 'active':
            findings = get_active_remediations(conn)
        else:
            findings = get_resolved_remediations(conn)
            
        if not findings:
            return pd.DataFrame()
            
        # Convert list of dictionaries to DataFrame
        df = pd.DataFrame.from_records(findings)
        
        # Convert date strings to datetime objects
        date_columns = ['due_date', 'first_seen', 'closed_date']
        for col in date_columns:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col])
        
        return df
    finally:
        conn.close() 