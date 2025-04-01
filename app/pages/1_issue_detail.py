import streamlit as st
import pandas as pd
from datetime import datetime
import sqlite3
from app.database.schema import get_db_connection
from app.components.IssuesList import render_issues_list

st.set_page_config(
    page_title="Issue Details",
    page_icon="🔒",
    layout="wide"
)

def get_issue_details(issue_id):
    """Get detailed information about a specific issue."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get issue and benchmark details
    cursor.execute('''
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
    WHERE i.id = ?
    ''', (issue_id,))
    
    issue = cursor.fetchone()
    if not issue:
        return None, None
    
    # Get all remediations for this issue
    cursor.execute('''
    SELECT 
        r.id,
        r.state,
        r.due_date,
        s_first.scan_date as first_seen,
        s_resolved.scan_date as resolved_date,
        f.failure,
        b.benchmark,
        b.finding_id
    FROM remediations r
    JOIN issue_remediations ir ON r.id = ir.remediation_id
    JOIN remediation_findings rf ON r.id = rf.remediation_id
    JOIN findings f ON rf.finding_id = f.id
    JOIN benchmark b ON r.benchmark_id = b.id
    LEFT JOIN scans s_first ON r.first_seen_scan = s_first.id
    LEFT JOIN scans s_resolved ON r.resolved_in_scan = s_resolved.id
    WHERE ir.issue_id = ?
    ORDER BY r.due_date ASC
    ''', (issue_id,))
    
    remediations = cursor.fetchall()
    conn.close()
    
    return issue, remediations

# Get issue ID from URL parameters
issue_id = st.query_params.get("id", [None])

if not issue_id:
    st.title("Security Issues")
    render_issues_list()
else:
    issue, remediations = get_issue_details(issue_id)

    if not issue:
        st.error(f"Issue {issue_id} not found.")
        st.stop()

    # Display issue details
    st.title(f"{issue['title']}")

    # Issue metadata
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("CVSS Score", f"{issue['cvss']:.1f}")
    with col2:
        st.metric("Level", issue['level'])
    with col3:
        st.metric("Status", issue['status'].upper())

    # Dates and timeline
    st.divider()
    date_col1, date_col2, date_col3 = st.columns(3)
    with date_col1:
        st.markdown(f"**Created:** {issue['created_at']}")
    with date_col2:
        st.markdown(f"**Due Date:** {issue['due_date']}")
    with date_col3:
        if issue['resolved_at']:
            st.markdown(f"**Resolved:** {issue['resolved_at']}")

    # Remediations table
    st.divider()
    st.subheader("Remediations")

    if remediations:
        remediation_data = []
        for r in remediations:
            remediation_data.append({
                'ID': r['id'],
                'State': r['state'].upper(),
                'Due Date': r['due_date'],
                'First Seen': r['first_seen'],
                'Resolved Date': r['resolved_date'] or '',
                'Finding ID': r['finding_id'],
                'Failure': r['failure']
            })
        
        df = pd.DataFrame(remediation_data)
        
        st.dataframe(
            df,
            column_config={
                'ID': st.column_config.NumberColumn('ID', width='small'),
                'State': st.column_config.TextColumn('State', width='small'),
                'Due Date': st.column_config.DateColumn('Due Date', width='small'),
                'First Seen': st.column_config.DateColumn('First Seen', width='small'),
                'Resolved Date': st.column_config.DateColumn('Resolved Date', width='small'),
                'Finding ID': st.column_config.TextColumn('Finding ID', width='medium'),
                'Failure': st.column_config.TextColumn('Failure', width='large')
            },
            hide_index=True,
            use_container_width=True
        )
    else:
        st.info("No remediations found for this issue.") 

    # Description and rationale
    st.divider()
    st.subheader("Description")
    st.write(issue['description'])

    if issue['rationale']:
        st.subheader("Rationale")
        st.write(issue['rationale'])

    # References
    if issue['refs']:
        st.divider()
        st.subheader("References")
        for ref in issue['refs'].split('\n'):
            if ref.strip():
                st.markdown(f"- [{ref}]({ref})")
