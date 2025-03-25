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
    create_issue_for_remediations,
    check_if_scan_exists
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
        if not cvss:
            return "Info"
        else:
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



def validate_columns(df, additional_columns=[]):
    """Validate columns in the CSV file."""
    required_columns = [
        'benchmark', 'id', 'level', 'cvss', 'title',
        'failures', 'description', 'rationale', 'refs'
    ]
    
    # Validate columns
    required_columns.extend(additional_columns)
    if not all(col in df.columns for col in required_columns):
        missing_cols = [col for col in required_columns if col not in df.columns]
        raise ValueError(f"Missing required columns: {', '.join(missing_cols)}")



def process_single_scan_upload(file, analysis_date):
    """Process a single scan upload."""
    df = pd.read_csv(file)
    return process_upload_dataframe(df, analysis_date)


def process_multiple_scan_upload(file):
    """Process a multiple scan upload with multiple analysis dates."""
    df = pd.read_csv(file)
    
    column_name_map = {
        'benchmark': 'Benchmark',
        'id': 'CIS_ID',
        'level': 'Level',
        'cvss': 'CVSS',
        'title': 'Title',
        'failures': 'Failures',
        'description': 'Description',
        'rationale': 'Rationale',
        'refs': 'References'
    }

    # Map from date to dataframe
    results = {
        'new': 0,
        'existing': 0,
        'resolved': 0
    }
    
    sorted_dates = sorted(df['Date'].unique(), key=lambda x: datetime.strptime(x, '%m/%d/%Y'))

    for date in sorted_dates:
        print(f"Processing date: {date}")
        date_obj = datetime.strptime(date, '%m/%d/%Y')
        # If we don't already have a scan for this date, create one
        conn = get_db_connection()
        if not check_if_scan_exists(conn, date_obj):
            this_data = df[df['Date'] == date]
            this_update = process_upload_dataframe(this_data, date_obj.strftime('%Y-%m-%d 00:00:00'), column_name_map)
            results['new'] += this_update['new']
            results['existing'] += this_update['existing']
            results['resolved'] += this_update['resolved']
        else:
            # Just log an continue
            print(f"Scan already exists for {date}, skipping")
            continue


    return results



def process_upload_dataframe(df: pd.DataFrame, analysis_date, column_name_map=None) -> dict:
    """Process a dataframe of uploaded CSV file and update database."""
    required_columns = [
        'benchmark', 'id', 'level', 'cvss', 'title',
        'failures', 'description', 'rationale', 'refs'
    ]

    if not column_name_map:
        column_name_map = { x: x for x in required_columns }
    
    # Validate columns
    if not all(column_name_map.get(col) in df.columns for col in required_columns):
        missing_cols = [column_name_map.get(col) for col in required_columns if column_name_map.get(col) not in df.columns]
        raise ValueError(f"Missing required columns: {', '.join(missing_cols)}")
    
    conn = get_db_connection()
    active_finding_ids = set()
    new_count = 0
    existing_count = 0
    
    try:
        # Get or create scan record
        scan_id = get_or_create_scan(conn, analysis_date)
        
        active_remediation_ids = set()
        remediations_needing_issues = {}
        
        # Process each row
        for _, row in df.iterrows():
            # Create benchmark record
            benchmark_data = (
                row[column_name_map['benchmark']],
                row[column_name_map['id']],  # This is the finding_id from CSV
                row[column_name_map['level']],
                float(row[column_name_map['cvss']]) if row[column_name_map['cvss']] else None,
                row[column_name_map['title']],
                row[column_name_map['description']],
                row[column_name_map['rationale']],
                row[column_name_map['refs']]
            )
            benchmark_id = get_or_create_benchmark(conn, benchmark_data)
            
            # Handle multiple failures
            failures = str(row[column_name_map['failures']]).split('\n')
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
                    active_remediation_ids.add(existing_remediation[0])
                    existing_count += 1
                else:
                    # Create new remediation
                    due_date = calculate_due_date(row[column_name_map['cvss']], analysis_date)
                    remediation_id = create_remediation(conn, benchmark_id, scan_id, due_date)
                    link_finding_to_remediation(conn, remediation_id, finding_id)
                    
                    # Add this remediation to the list of active remediations:
                    active_remediation_ids.add(remediation_id)

                    # Add this remediation to the list of remediations needing issues:
                    remediations_for_this_benchmark: list[int] = remediations_needing_issues.get((benchmark_id, due_date), [])
                    remediations_for_this_benchmark.append(remediation_id)
                    remediations_needing_issues[(benchmark_id, due_date)] = remediations_for_this_benchmark
                    new_count += 1

        for (benchmark_id, due_date), remediation_ids in remediations_needing_issues.items():
            create_issue_for_remediations(conn, remediation_ids, benchmark_id, created_at=analysis_date, due_date=due_date)
        
        # Mark findings as resolved if they're not in current upload
        mark_remediations_resolved_if_not_in_list(conn, scan_id, active_remediation_ids)
        
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

def export_issues_to_df(status='open'):
    """Export issues to a DataFrame."""
    conn = get_db_connection()
    cursor = conn.cursor()
    

    sql = '''
    SELECT 
        i.id,
        i.due_date,
        i.created_at,
        i.resolved_at,
        i.status,
        b.benchmark,
        b.finding_id,
        b.level,
        b.cvss,
        b.title,
        b.description,
        b.rationale,
        b.refs
    FROM issues i
    JOIN benchmark b ON i.benchmark_id = b.id
    WHERE i.status = ?
    '''
    
    cursor.execute(sql, (status,))
    
    # Convert list of dictionaries to DataFrame
    issues = [dict(row) for row in cursor.fetchall()]

    df = pd.DataFrame.from_records(issues)
    
    # Convert date strings to datetime objects
    date_columns = ['due_date', 'created_at', 'resolved_at']
    for col in date_columns:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col])
    
    return df 
