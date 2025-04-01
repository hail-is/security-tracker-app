import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
from app.components.data_processor import (
    process_single_scan_upload,
    process_multiple_scan_upload,
    get_findings_summary
)

from app.components.IssuesList import render_issues_list
import os
import logging
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

def get_due_date_status(due_date: pd.Timestamp):
    """Return the status and style for a due date."""
    if not due_date:
        return "", ""
    
    today: datetime.date = datetime.now().date()
    due_date: datetime.date = pd.to_datetime(due_date).date()
    
    # Type safe comparison:
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
    # Show a dropdown to select the type of upload
    upload_type = st.selectbox("Upload Type", ["Single Scan", "Multiple Scans"])
    st.subheader("Upload Single Scan")
    uploaded_file = st.file_uploader("Select CSV File", type="csv", key="file_uploader")
    
    if upload_type == "Single Scan":    
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
                if upload_type == "Single Scan":
                    results = process_single_scan_upload(uploaded_file, analysis_date.strftime('%Y-%m-%d 00:00:00'))
                elif upload_type == "Multiple Scans":
                    results = process_multiple_scan_upload(uploaded_file)
                st.session_state.open_modal = False
                st.session_state.show_success = True
                st.session_state.upload_results = results
                st.rerun()

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

# Issues List with Tabs
render_issues_list()
