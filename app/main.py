import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
from app.components.data_processor import (
    process_csv_upload,
    get_findings_summary,
    export_findings_to_df
)
import os

# Set page config
st.set_page_config(
    page_title="Security Findings Tracker",
    page_icon="🔒",
    layout="wide"
)

# Initialize session state variables
if 'open_modal' not in st.session_state:
    st.session_state.open_modal = False
if 'show_success' not in st.session_state:
    st.session_state.show_success = False
if 'upload_results' not in st.session_state:
    st.session_state.upload_results = {}

# Load custom CSS
with open(os.path.join(os.path.dirname(__file__), "static/style.css")) as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

def get_due_date_status(due_date):
    """Return the status and style for a due date."""
    if not due_date:
        return "", ""
    
    today = datetime.now().date()
    due_date = datetime.strptime(due_date, '%Y-%m-%d 00:00:00').date() if isinstance(due_date, str) else due_date
    
    if due_date < today:
        return "❗ ", "overdue"
    elif due_date <= today + timedelta(days=7):
        return "⚠️ ", "warning"
    return "", ""

# Header with Upload Button
col1, col2 = st.columns([3, 1])
with col1:
    st.markdown("""
    <div class="main-header">
        <h1>Security Findings Tracker</h1>
    </div>
    """, unsafe_allow_html=True)
with col2:
    if st.button("Upload Findings", type="primary", use_container_width=True):
        st.session_state.open_modal = True

# Upload Modal Dialog
@st.dialog("Upload Security Findings")
def show_upload_dialog():
    st.subheader("Upload New Findings")
    uploaded_file = st.file_uploader("Select CSV File", type="csv", key="file_uploader")
    analysis_date = st.date_input(
        "Analysis Date",
        value=datetime.now().date(),
        key="analysis_date",
        help="Date when the security analysis was performed"
    )
    
    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("Cancel", type="secondary"):
            st.session_state.open_modal = False
            st.rerun()
    with col2:
        if uploaded_file is not None:
            if st.button("Confirm Upload", type="primary"):
                try:
                    results = process_csv_upload(uploaded_file, analysis_date.strftime('%Y-%m-%d 00:00:00'))
                    st.session_state.open_modal = False
                    st.session_state.show_success = True
                    st.session_state.upload_results = results
                    st.rerun()
                except Exception as e:
                    st.error(f"Error processing file: {str(e)}")

# Call the dialog function
if st.session_state.open_modal:
    show_upload_dialog()

# Show success message after upload
if st.session_state.pop("show_success", False):
    results = st.session_state.pop("upload_results", {})
    st.success("File processed successfully!")
    st.markdown("### Upload Summary")
    st.markdown(f"""
    - New Findings: {results['new']}
    - Updated Findings: {results['existing']}
    - Resolved Findings: {results['resolved']}
    """)

# Main Content
summary = get_findings_summary()

# Charts Section
col1, col2, col3, col4 = st.columns(4)

with col1:
    with st.container(border=True):
        # Active Findings
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-number">{summary['active_count']}</div>
            <div class="stat-label">Active Findings</div>
        </div>
        """, unsafe_allow_html=True)

        # Due This Week
        due_this_week = summary.get('due_this_week', 0)
        st.markdown(f"""
        <div class="stat-card {'warning-stat' if due_this_week > 0 else ''}">
            <div class="stat-number">{'⚠️ ' if due_this_week > 0 else ''}{due_this_week}</div>
            <div class="stat-label">Due This Week</div>
        </div>
        """, unsafe_allow_html=True)

        # Overdue Findings
        overdue_count = summary.get('overdue_count', 0)
        st.markdown(f"""
        <div class="stat-card {'overdue-stat' if overdue_count > 0 else ''}">
            <div class="stat-number">{'❗ ' if overdue_count > 0 else ''}{overdue_count}</div>
            <div class="stat-label">Overdue Findings</div>
        </div>
        """, unsafe_allow_html=True)

with col2:
    # Level distribution chart
    level_df = pd.DataFrame([
        {'Level': k, 'Count': v}
        for k, v in summary['severity_counts'].items()
    ])
    
    if not level_df.empty:
        fig1 = px.pie(
            level_df,
            values='Count',
            names='Level',
            title='Active Findings by Level',
            color='Level',
            color_discrete_map={
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#20c997',
                'info': '#0dcaf0'
            }
        )
        fig1.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig1, use_container_width=True)

with col3:
    # CVSS distribution chart
    if 'cvss_counts' in summary:
        cvss_df = pd.DataFrame([
            {'CVSS Range': k, 'Count': v}
            for k, v in summary['cvss_counts'].items()
        ])
        
        if not cvss_df.empty:
            fig2 = px.pie(
                cvss_df,
                values='Count',
                names='CVSS Range',
                title='Active Findings by CVSS',
                color='CVSS Range',
                color_discrete_sequence=px.colors.sequential.RdBu
            )
            fig2.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig2, use_container_width=True)

with col4:
    # Due by date chart
    overdue_count = summary.get('overdue_count', 0)
    due_this_week = summary.get('due_this_week', 0)
    due_within_28_days = summary.get('due_within_28_days', 0)
    due_after_28_days = summary.get('due_after_28_days', 0)
    
    fig3 = px.pie(
        values=[overdue_count, due_this_week, due_within_28_days, due_after_28_days],
        names=['Overdue', 'Due This Week', 'Due Within 28 Days', 'Due After 28 Days'],
        title='Active Findings by Due Date',
        color_discrete_sequence=px.colors.sequential.RdBu
    )
    st.plotly_chart(fig3, use_container_width=True)



# Findings Tables
tab1, tab2 = st.tabs(["Active Findings", "Resolved Findings"])

ROWS_PER_PAGE = 5

with tab1:
    active_df = export_findings_to_df(status='active')
    if not active_df.empty:
        # Add status indicators
        grouped_df = active_df.groupby(['benchmark', 'finding_id', 'due_date', 'level', 'cvss', 'title', 'description', 'rationale', 'refs']).agg({
            'failure': lambda x: '\n'.join(x),
            'first_seen': 'min'
        }).reset_index()
        
        # Add status column
        grouped_df['status_icon'], grouped_df['status'] = zip(*grouped_df['due_date'].apply(get_due_date_status))
        
        # Sort by due_date and cvss
        grouped_df = grouped_df.sort_values(['due_date', 'cvss'], ascending=[True, False])
        
        # Create style conditions for row highlighting
        def style_dataframe(df):
            today = datetime.now().date()
            
            def row_style(row):
                due_date = row['due_date'].date() if isinstance(row['due_date'], pd.Timestamp) else datetime.strptime(row['due_date'], '%Y-%m-%d 00:00:00').date()
                
                if due_date < today:
                    return ['background-color: #f8d7da'] * len(row)
                elif due_date <= today + timedelta(days=7):
                    return ['background-color: #fff3cd'] * len(row)
                return [''] * len(row)
            
            return df.style.apply(row_style, axis=1)
        
        # Pagination
        total_pages = len(grouped_df) // ROWS_PER_PAGE + (1 if len(grouped_df) % ROWS_PER_PAGE > 0 else 0)
        page = st.session_state.get(f"page_active", 0)
        start_idx = page * ROWS_PER_PAGE
        end_idx = start_idx + ROWS_PER_PAGE
        
        # Apply styling to the visible portion of the dataframe
        visible_df = grouped_df.iloc[start_idx:end_idx].copy()
        styled_df = style_dataframe(visible_df)
        
        # Create the dataframe display
        st.dataframe(
            styled_df,
            column_config={
                "status_icon": st.column_config.TextColumn(
                    "",
                    width=40,
                ),
                "level": st.column_config.TextColumn(
                    "Level",
                    help="Finding severity level",
                    width=40
                ),
                "cvss": st.column_config.NumberColumn(
                    "CVSS",
                    help="CVSS score",
                    width=40,
                    format="%.1f"
                ),
                "first_seen": st.column_config.DateColumn(
                    "First Seen",
                    format="YYYY-MM-DD",
                    width=100
                ),
                "due_date": st.column_config.DateColumn(
                    "Due Date",
                    format="YYYY-MM-DD",
                    width=100
                ),
                "title": st.column_config.TextColumn(
                    "Title",
                    width=300,
                    help="Finding title",
                    max_chars=100
                ),
                "description": st.column_config.TextColumn(
                    "Description",
                    width=400,
                    help="Finding description",
                    max_chars=100
                ),
                "failure": st.column_config.TextColumn(
                    "Failures",
                    width=400,
                    help="List of failures for this finding",
                    max_chars=100
                ),
                "refs": st.column_config.LinkColumn(
                    "References",
                    help="Reference links",
                    max_chars=50,
                    width=150
                )
            },
            hide_index=True,
            use_container_width=True,
            column_order=["status_icon", "due_date", "level", "cvss", "title", "description", "failure", "first_seen", "refs"],
            row_height=100,
            height=550,
        )

        # Pagination controls in columns for better layout
        col1, col2, col3 = st.columns([1, 2, 1])
        with col1:
            if st.button("← Previous", disabled=(page == 0)):
                st.session_state[f"page_active"] = max(0, page - 1)
                st.rerun()
        with col2:
            st.markdown(f"Page {page + 1} of {total_pages}")
        with col3:
            if st.button("Next →", disabled=(page >= total_pages - 1)):
                st.session_state[f"page_active"] = min(total_pages - 1, page + 1)
                st.rerun()
        
        # Export button
        csv = grouped_df.to_csv(index=False)
        st.download_button(
            "Export Active Findings",
            csv,
            "active_findings.csv",
            "text/csv",
            key='download-active-csv'
        )
    else:
        st.info("No active findings.")

with tab2:
    resolved_df = export_findings_to_df(status='resolved')
    if not resolved_df.empty:
        # Group resolved findings similarly
        grouped_resolved_df = resolved_df.groupby(['benchmark', 'finding_id', 'closed_date', 'level', 'cvss', 'title', 'description', 'rationale', 'refs']).agg({
            'failure': lambda x: '\n'.join(x),
            'first_seen': 'min'
        }).reset_index()
        
        # Sort by closed_date and cvss
        grouped_resolved_df = grouped_resolved_df.sort_values(['closed_date', 'cvss'], ascending=[False, False])
        
        # Pagination for resolved findings
        total_pages_resolved = len(grouped_resolved_df) // ROWS_PER_PAGE + (1 if len(grouped_resolved_df) % ROWS_PER_PAGE > 0 else 0)
        page_resolved = st.session_state.get(f"page_resolved", 0)
        start_idx = page_resolved * ROWS_PER_PAGE
        end_idx = start_idx + ROWS_PER_PAGE
        
        st.dataframe(
            grouped_resolved_df.iloc[start_idx:end_idx],
            column_config={
                "level": st.column_config.TextColumn(
                    "Level",
                    help="Finding severity level",
                    width="small"
                ),
                "cvss": st.column_config.NumberColumn(
                    "CVSS",
                    help="CVSS score",
                    width="small"
                ),
                "first_seen": st.column_config.DateColumn(
                    "First Seen",
                    format="YYYY-MM-DD",
                    width="medium"
                ),
                "closed_date": st.column_config.DateColumn(
                    "Closed Date",
                    format="YYYY-MM-DD",
                    width="medium"
                ),
                "failure": st.column_config.TextColumn(
                    "Failures",
                    width="large",
                    help="List of failures for this finding"
                )
            },
            hide_index=True,
            use_container_width=True
        )
        
                # Pagination controls in columns for better layout
        col1, col2, col3 = st.columns([1, 2, 1])
        with col1:
            if st.button("← Previous", disabled=(page_resolved == 0)):
                st.session_state[f"page_resolved"] = max(0, page_resolved - 1)
                st.rerun()
        with col2:
            st.markdown(f"Page {page_resolved + 1} of {total_pages_resolved}")
        with col3:
            if st.button("Next →", disabled=(page_resolved >= total_pages_resolved - 1)):
                st.session_state[f"page_resolved"] = min(total_pages_resolved - 1, page_resolved + 1)
                st.rerun()
        
        # Export button
        csv = grouped_resolved_df.to_csv(index=False)
        st.download_button(
            "Export Resolved Findings",
            csv,
            "resolved_findings.csv",
            "text/csv",
            key='download-resolved-csv'
        )
    else:
        st.info("No resolved findings.")
