import streamlit as st
import pandas as pd
from app.database.schema import get_db_connection
from app.components.IssuesList import render_issues_list

st.set_page_config(
    page_title="Benchmark Details",
    page_icon="🔒",
    layout="wide"
)

def get_all_benchmarks():
    """Get a list of all benchmarks with their stats."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
    SELECT 
        b.id,
        b.benchmark,
        b.finding_id,
        b.level,
        b.cvss,
        b.title,
        COUNT(DISTINCT i.id) as total_issues,
        SUM(CASE WHEN i.status = 'open' THEN 1 ELSE 0 END) as open_issues,
        COUNT(DISTINCT r.id) as total_remediations,
        SUM(CASE WHEN r.state = 'open' THEN 1 ELSE 0 END) as open_remediations
    FROM benchmark b
    LEFT JOIN issues i ON b.id = i.benchmark_id
    LEFT JOIN issue_remediations ir ON i.id = ir.issue_id
    LEFT JOIN remediations r ON ir.remediation_id = r.id
    GROUP BY b.id
    ORDER BY b.cvss DESC
    ''')
    
    columns = [column[0] for column in cursor.description]
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    
    return pd.DataFrame(rows) if rows else pd.DataFrame()

def get_benchmark_details(benchmark_id):
    """Get detailed information about a specific benchmark."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get benchmark details
    cursor.execute('''
    SELECT 
        b.id,
        b.benchmark,
        b.finding_id,
        b.level,
        b.cvss,
        b.title,
        b.description,
        b.rationale,
        b.refs
    FROM benchmark b
    WHERE b.id = ?
    ''', (benchmark_id,))
    
    benchmark = cursor.fetchone()
    if not benchmark:
        return None, None, None
    
    # Get all issues for this benchmark
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
        COUNT(r.id) as remediation_count
    FROM issues i
    JOIN benchmark b ON i.benchmark_id = b.id
    JOIN issue_remediations ir ON i.id = ir.issue_id
    JOIN remediations r ON ir.remediation_id = r.id
    WHERE b.id = ?
    GROUP BY i.id
    ORDER BY i.created_at DESC
    ''', (benchmark_id,))
    
    issues = [dict(zip([column[0] for column in cursor.description], row)) 
             for row in cursor.fetchall()]
    
    # Get all open remediations for this benchmark
    cursor.execute('''
    SELECT 
        r.id,
        r.state,
        r.due_date,
        s_first.scan_date as first_seen,
        s_resolved.scan_date as resolved_date,
        f.failure,
        i.id as issue_id
    FROM remediations r
    JOIN issue_remediations ir ON r.id = ir.remediation_id
    JOIN issues i ON ir.issue_id = i.id
    JOIN remediation_findings rf ON r.id = rf.remediation_id
    JOIN findings f ON rf.finding_id = f.id
    LEFT JOIN scans s_first ON r.first_seen_scan = s_first.id
    LEFT JOIN scans s_resolved ON r.resolved_in_scan = s_resolved.id
    WHERE r.benchmark_id = ? AND r.state = 'open'
    ORDER BY r.due_date ASC
    ''', (benchmark_id,))
    
    remediations = [dict(zip([column[0] for column in cursor.description], row)) 
                   for row in cursor.fetchall()]
    
    conn.close()
    return benchmark, issues, remediations

def get_issue_page_link(id: str):
    """Link to the issue detail page with id as query parameter"""
    return f'/issue_detail?id={id}'

def get_benchmark_page_link(id: str):
    """Link to the benchmark detail page with id as query parameter"""
    return f'/benchmark_detail?id={id}'

# Get benchmark ID from URL parameters
benchmark_id = st.query_params.get("id", None)

if not benchmark_id:
    st.title("Security Benchmarks")
    
    # Show table of all benchmarks
    benchmarks_df = get_all_benchmarks()
    if not benchmarks_df.empty:
        # Add link to benchmark details
        benchmarks_df['details_page'] = benchmarks_df['id'].apply(get_benchmark_page_link)
        
        st.dataframe(
            benchmarks_df,
            column_config={
                'id': st.column_config.NumberColumn('ID', width='small'),
                'benchmark': st.column_config.TextColumn('Benchmark', width='medium'),
                'finding_id': st.column_config.TextColumn('Finding ID', width='small'),
                'level': st.column_config.TextColumn('Level', width='small'),
                'cvss': st.column_config.NumberColumn('CVSS', format="%.1f", width='small'),
                'title': st.column_config.TextColumn('Title', width='large'),
                'total_issues': st.column_config.NumberColumn('Total Issues', width='small'),
                'open_issues': st.column_config.NumberColumn('Open Issues', width='small'),
                'total_remediations': st.column_config.NumberColumn('Total Remediations', width='small'),
                'open_remediations': st.column_config.NumberColumn('Open Remediations', width='small'),
                'details_page': st.column_config.LinkColumn('Details', display_text="View", width='small')
            },
            hide_index=True,
            use_container_width=True
        )
    else:
        st.info("No benchmarks found.")
else:
    # Get benchmark details
    benchmark, issues, remediations = get_benchmark_details(benchmark_id)
    
    if not benchmark:
        st.error(f"Benchmark {benchmark_id} not found.")
        st.stop()
    
    # Basic breadcrumbs
    st.markdown(f"""
    <div style="display: flex; align-items: center; gap: 10px;">
        <a href="/benchmark_detail", target="_self">Benchmarks</a>
        <span style="color: #888;"> > </span>
        <a href="/benchmark_detail?id={benchmark_id}", target="_self">{benchmark['finding_id']}</a>
    </div>
    """, unsafe_allow_html=True)
    
    # Display benchmark details
    st.title(f"{benchmark['title']}")
    
    # Benchmark metadata
    col1, col2 = st.columns(2)
    with col1:
        st.metric("CVSS Score", f"{benchmark['cvss']:.1f}")
    with col2:
        st.metric("Level", benchmark['level'])
    
    # Issues list
    st.divider()
    st.subheader("Issues")
    if issues:
        issues_df = pd.DataFrame(issues)
        issues_df['details_page'] = issues_df['id'].apply(get_issue_page_link)
        render_issues_list(issues_df)
    else:
        st.info("No issues found for this benchmark.")
    
    # Open remediations
    st.divider()
    st.subheader("Open Remediations")
    if remediations:
        remediations_df = pd.DataFrame(remediations)
        # Add link to the issue for each remediation
        remediations_df['issue_link'] = remediations_df['issue_id'].apply(get_issue_page_link)
        
        st.dataframe(
            remediations_df,
            column_config={
                'id': st.column_config.NumberColumn('ID', width='small'),
                'state': st.column_config.TextColumn('State', width='small'),
                'due_date': st.column_config.DateColumn('Due Date', width='small'),
                'first_seen': st.column_config.DateColumn('First Seen', width='small'),
                'failure': st.column_config.TextColumn('Failure', width='large'),
                'issue_link': st.column_config.LinkColumn('Issue', display_text="View Issue", width='small')
            },
            hide_index=True,
            use_container_width=True
        )
    else:
        st.info("No open remediations for this benchmark.") 

    # Description and rationale
    st.divider()
    st.subheader("Description")
    st.write(benchmark['description'])
    
    if benchmark['rationale']:
        st.subheader("Rationale")
        st.write(benchmark['rationale'])
    
    # References
    if benchmark['refs']:
        st.divider()
        st.subheader("References")
        for ref in benchmark['refs'].split('\n'):
            if ref.strip():
                st.markdown(f"- [{ref}]({ref})")
