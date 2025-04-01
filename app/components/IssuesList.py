import streamlit as st
import pandas as pd
from app.components.data_processor import export_issues_to_df
from app.components.IssuesTable import render_issues_table
from typing import Optional

def render_issues_list(df_in: Optional[pd.DataFrame] = None):
    """
    Renders a tabbed interface showing active and resolved issues.
    """
    tab1, tab2 = st.tabs(["Active Issues", "Resolved Issues"])

    def render_tab_content(status, label):
        if df_in is None:
            df = export_issues_to_df(status=status)
        else:
            # Filter by status
            df = df_in[df_in['status'] == status]

        if not df.empty:
            render_issues_table(df)
        else:
            st.info(f"No {label.lower()}.")

    with tab1:
        render_tab_content('open', 'Active Findings')

    with tab2:
        render_tab_content('resolved', 'Resolved Findings') 