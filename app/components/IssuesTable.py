import streamlit as st
import pandas as pd
from datetime import datetime, timedelta

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


def style_dataframe(df):
    """Apply conditional styling to the dataframe based on due dates."""
    today = datetime.now().date()
    
    def row_style(row):
        if 'due_date' not in row:
            return [''] * len(row)
            
        due_date = row['due_date'].date() if isinstance(row['due_date'], pd.Timestamp) else datetime.strptime(row['due_date'], '%Y-%m-%d 00:00:00').date()
        
        if due_date < today:
            return ['background-color: #f8d7da'] * len(row)
        elif due_date <= today + timedelta(days=7):
            return ['background-color: #fff3cd'] * len(row)
        return [''] * len(row)
    
    return df.style.apply(row_style, axis=1)


def get_issue_page_link(id: str):
    """Link to the issue detail page with id as query parameter"""
    return f'/issue_detail?id={id}'


def render_issues_table(
    df: pd.DataFrame,
    with_pagination: bool = False,
    rows_per_page: int = 5,
    page_key: str = "page",
):
    """
    Render a table of security issues with consistent styling and optional pagination.
    
    Args:
        df: DataFrame containing the issues data
        with_pagination: Whether to enable pagination (defaults to False)
        rows_per_page: Number of rows per page when pagination is enabled
        page_key: Key to use for the pagination state in session state
    """
    if df.empty:
        st.info("No issues to display.")
        return

    # Add status indicators if not already present
    if 'status_icon' not in df.columns and 'due_date' in df.columns:
        df['status_icon'], df['status'] = zip(*df['due_date'].apply(get_due_date_status))

    # Sort by due_date and cvss if present
    if 'due_date' in df.columns and 'cvss' in df.columns:
        df = df.sort_values(['due_date', 'cvss'], ascending=[True, False])

    # Add issue_link column
    df['issue_link'] = df['id'].apply(get_issue_page_link)

    # Handle pagination if enabled
    if with_pagination:
        total_pages = len(df) // rows_per_page + (1 if len(df) % rows_per_page > 0 else 0)
        page = st.session_state.get(page_key, 0)
        start_idx = page * rows_per_page
        end_idx = start_idx + rows_per_page
        display_df = style_dataframe(df.iloc[start_idx:end_idx].copy())
    else:
        display_df = style_dataframe(df)

    # Define column configuration - more compact version matching scan details
    column_config = {
        "status_icon": st.column_config.TextColumn(
            "",
            width="small"
        ),
        "issue_link": st.column_config.LinkColumn(
            "Details",
            help="Click to view issue details",
            display_text="View",
            width="small",
        ),
        "benchmark": st.column_config.TextColumn(
            "Benchmark",
            width="medium"
        ),
        "finding_id": st.column_config.TextColumn(
            "Finding ID",
            width="small"
        ),
        "level": st.column_config.TextColumn(
            "Level",
            width="small"
        ),
        "cvss": st.column_config.NumberColumn(
            "CVSS",
            format="%.1f",
            width="small"
        ),
        "title": st.column_config.TextColumn(
            "Title",
            width="large"
        ),
        "remediation_count": st.column_config.NumberColumn(
            "Remediations",
            width="small"
        ),
        "created_at": st.column_config.DateColumn(
            "Created",
            width="small"
        ),
        "resolved_at": st.column_config.DateColumn(
            "Resolved",
            width="small"
        ),
        "due_date": st.column_config.DateColumn(
            "Due Date",
            format="YYYY-MM-DD",
            width="small"
        ),
        "failure": st.column_config.TextColumn(
            "Failure",
            width="large"
        ),
        "first_seen": st.column_config.DateColumn(
            "First Seen",
            width="small"
        )
    }

    # Only include columns that exist in the dataframe
    filtered_config = {k: v for k, v in column_config.items() if k in df.columns}
    
    # Define default column order - matching scan details layout
    default_columns = [
        "status_icon", 
        "issue_link",
        "benchmark", "finding_id", 
        "level", "cvss", "title", "remediation_count",
        "created_at", "resolved_at", "due_date", "failure", "first_seen"
    ]
    
    # Filter column order to only include columns that exist in the dataframe
    column_order = [col for col in default_columns if col in df.columns]

    # Display the dataframe with compact styling
    st.dataframe(
        display_df,
        column_config=filtered_config,
        hide_index=True,
        column_order=column_order,
        use_container_width=True
    )

    # Render pagination controls if enabled
    if with_pagination:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col1:
            if st.button("← Previous", disabled=(page == 0)):
                st.session_state[page_key] = max(0, page - 1)
                st.rerun()
        with col2:
            st.markdown(f"Page {page + 1} of {total_pages}")
        with col3:
            if st.button("Next →", disabled=(page >= total_pages - 1)):
                st.session_state[page_key] = min(total_pages - 1, page + 1)
                st.rerun() 