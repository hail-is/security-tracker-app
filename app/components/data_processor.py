import pandas as pd
from datetime import datetime, timedelta
from app.database.schema import (
    get_db_connection,
    insert_finding,
    mark_findings_resolved,
    get_active_findings
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
    current_finding_keys = set()
    new_count = 0
    existing_count = 0
    
    try:
        # Process each row
        for _, row in df.iterrows():
            # Handle multiple failures
            failures = str(row['failures']).split('\n')
            for failure in failures:
                failure = failure.strip()
                if not failure:
                    continue
                
                # Create unique key for finding using benchmark + finding_id + failure
                finding_key = f"{row['benchmark']}|{row['id']}|{failure}"
                current_finding_keys.add(finding_key)
                
                # Check if finding exists
                cursor = conn.cursor()
                cursor.execute('''
                SELECT first_seen, due_date FROM findings
                WHERE benchmark = ? AND finding_id = ? AND failure = ?
                AND resolved_status = FALSE
                ''', (row['benchmark'], row['id'], failure))
                existing_finding = cursor.fetchone()
                
                first_seen = analysis_date
                calculated_due_date = calculate_due_date(row['cvss'], analysis_date)


                if existing_finding:
                    # Update existing finding
                    earliest_due_date = min(calculated_due_date, datetime.strptime(existing_finding['due_date'], '%Y-%m-%d 00:00:00'))
                    due_date = earliest_due_date
                    first_seen = existing_finding['first_seen']
                    existing_count += 1
                else:
                    # Create new finding
                    due_date = calculated_due_date
                    new_count += 1
                
                # Insert or update finding
                finding_data = (
                    row['benchmark'],
                    row['id'],  # This is the finding_id from CSV
                    row['level'],
                    row['cvss'],
                    row['title'],
                    failure,
                    row['description'],
                    row['rationale'],
                    row['refs'],
                    first_seen,
                    due_date,
                    False,  # resolved_status
                    None   # closed_date
                )
                insert_finding(conn, finding_data)
        
        # Mark findings as resolved if they're not in current upload
        mark_findings_resolved(conn, analysis_date, current_finding_keys)
        
        # Get count of resolved findings
        cursor = conn.cursor()
        cursor.execute('''
        SELECT COUNT(*) as count FROM findings
        WHERE closed_date = ?
        ''', (analysis_date,))
        resolved_count = cursor.fetchone()['count']
        
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
        
        # Get active findings
        cursor.execute('''
        SELECT COUNT(*) as count FROM findings
        WHERE resolved_status = FALSE
        ''')
        active_count = cursor.fetchone()['count']
        
        # Get resolved findings
        cursor.execute('''
        SELECT COUNT(*) as count FROM findings
        WHERE resolved_status = TRUE
        ''')
        resolved_count = cursor.fetchone()['count']
        
        # Get findings by severity
        cursor.execute('''
        SELECT level, COUNT(*) as count FROM findings
        WHERE resolved_status = FALSE
        GROUP BY level
        ''')
        severity_counts = {row['level']: row['count'] for row in cursor.fetchall()}
        
        # Get findings by CVSS
        cursor.execute('''
        SELECT cvss FROM findings
        WHERE resolved_status = FALSE
        ''')
        cvss_scores = [row['cvss'] for row in cursor.fetchall()]
        cvss_ranges = [get_cvss_range(score) for score in cvss_scores]
        cvss_counts = pd.Series(cvss_ranges).value_counts().to_dict()
        
        
        # Get findings due within 28 days
        today = datetime.now().date()
        twenty_eight_day_time_period_end = today + timedelta(days=28)
        cursor.execute('''
        SELECT COUNT(*) as count FROM findings
        WHERE resolved_status = FALSE
        AND due_date <= ?
        AND due_date > ?
        ''', (twenty_eight_day_time_period_end.strftime('%Y-%m-%d'), today.strftime('%Y-%m-%d')))
        due_within_28_days = cursor.fetchone()['count']
        
        # Get findings due this week
        week_end = today + timedelta(days=7)
        cursor.execute('''
        SELECT COUNT(*) as count FROM findings
        WHERE resolved_status = FALSE
        AND due_date <= ?
        AND due_date > ?
        ''', (week_end.strftime('%Y-%m-%d'), today.strftime('%Y-%m-%d')))
        due_this_week = cursor.fetchone()['count']
        
        # Get overdue findings
        cursor.execute('''
        SELECT COUNT(*) as count FROM findings
        WHERE resolved_status = FALSE
        AND due_date < ?
        ''', (today.strftime('%Y-%m-%d'),))
        overdue_count = cursor.fetchone()['count']

         # Get findings due after more than 28 days
        param = twenty_eight_day_time_period_end.strftime('%Y-%m-%d')
        print(param)
        cursor.execute('''
        SELECT COUNT(*) as count FROM findings
        WHERE resolved_status = FALSE
        AND due_date > ?
        ''', (param,))
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
        query = '''
        SELECT * FROM findings
        WHERE resolved_status = ?
        ORDER BY due_date ASC
        '''
        df = pd.read_sql_query(query, conn, params=(status == 'resolved',))
        return df
    finally:
        conn.close() 