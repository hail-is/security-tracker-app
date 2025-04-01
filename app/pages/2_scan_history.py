import streamlit as st
import pandas as pd
from datetime import datetime
from app.database.schema import get_db_connection
from app.components.IssuesTable import render_issues_table

st.set_page_config(
    page_title="Scan History",
    page_icon="🔒",
    layout="wide"
)

def get_all_scans():
    """Get list of all scans ordered by date."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT id, scan_date
    FROM scans
    ORDER BY scan_date DESC
    ''')
    return [dict(row) for row in cursor.fetchall()]

def get_scan_details(scan_id):
    """Get detailed information about a specific scan."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get basic scan info
    cursor.execute('''
    SELECT id, scan_date
    FROM scans
    WHERE id = ?
    ''', (scan_id,))
    scan = cursor.fetchone()
    
    if not scan:
        return None, None, None, None
    
    # Get new issues from this scan
    cursor.execute('''
    SELECT 
        i.id,
        i.due_date,
        i.created_at,
        b.benchmark,
        b.finding_id,
        b.level,
        b.cvss,
        b.title,
        COUNT(r.id) as remediation_count
    FROM issues i
    JOIN benchmark b ON i.benchmark_id = b.id
    JOIN issue_remediations ir ON i.id = ir.issue_id
    JOIN remediations r ON ir.remediation_id = r.id
    WHERE DATE(i.created_at) = DATE(?)
    GROUP BY i.id
    ORDER BY b.cvss DESC
    ''', (scan['scan_date'],))
    new_issues = [dict(row) for row in cursor.fetchall()]
    
    # Get issues closed in this scan
    cursor.execute('''
    SELECT 
        i.id,
        i.due_date,
        i.created_at,
        i.resolved_at,
        b.benchmark,
        b.finding_id,
        b.level,
        b.cvss,
        b.title,
        COUNT(r.id) as remediation_count
    FROM issues i
    JOIN benchmark b ON i.benchmark_id = b.id
    JOIN issue_remediations ir ON i.id = ir.issue_id
    JOIN remediations r ON ir.remediation_id = r.id
    WHERE DATE(i.resolved_at) = DATE(?)
    GROUP BY i.id
    ORDER BY b.cvss DESC
    ''', (scan['scan_date'],))
    closed_issues = [dict(row) for row in cursor.fetchall()]
    
    # Get findings resolved in this scan
    cursor.execute('''
    SELECT 
        b.benchmark,
        b.finding_id,
        b.level,
        b.cvss,
        b.title,
        f.failure,
        r.due_date,
        s_first.scan_date as first_seen
    FROM remediations r
    JOIN benchmark b ON r.benchmark_id = b.id
    JOIN remediation_findings rf ON r.id = rf.remediation_id
    JOIN findings f ON rf.finding_id = f.id
    JOIN scans s_first ON r.first_seen_scan = s_first.id
    WHERE r.resolved_in_scan = ?
    ORDER BY b.cvss DESC
    ''', (scan_id,))
    resolved_findings = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return scan, new_issues, closed_issues, resolved_findings

# Get list of all scans
scans = get_all_scans()

if not scans:
    st.error("No scans found in the database.")
    st.stop()

# Scan selector
selected_scan = st.selectbox(
    "Select Scan",
    options=scans,
    format_func=lambda x: x['scan_date'],
    key="scan_selector"
)

if selected_scan:
    scan, new_issues, closed_issues, resolved_findings = get_scan_details(selected_scan['id'])
    
    if not scan:
        st.error(f"Scan {selected_scan['id']} not found.")
        st.stop()
    
    # Display scan summary
    st.title(f"Scan Details: {scan['scan_date']}")
    
    # Summary metrics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("New Issues", len(new_issues))
    with col2:
        st.metric("Closed Issues", len(closed_issues))
    with col3:
        st.metric("Resolved Findings", len(resolved_findings))
    
    # New Issues
    st.divider()
    st.subheader("New Issues")
    if new_issues:
        new_issues_df = pd.DataFrame(new_issues)
        new_issues_df['issue_link'] = [f"/issue_detail?id={issue['id']}" for issue in new_issues]
        render_issues_table(new_issues_df)
    else:
        st.info("No new issues in this scan.")
    
    # Closed Issues
    st.divider()
    st.subheader("Closed Issues")
    if closed_issues:
        closed_issues_df = pd.DataFrame(closed_issues)
        render_issues_table(closed_issues_df)
    else:
        st.info("No issues were closed in this scan.")
    
    # Resolved Findings
    st.divider()
    st.subheader("Resolved Findings")
    if resolved_findings:
        resolved_findings_df = pd.DataFrame(resolved_findings)
        render_issues_table(resolved_findings_df)
    else:
        st.info("No findings were resolved in this scan.") 