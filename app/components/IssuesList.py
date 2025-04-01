import streamlit as st
import pandas as pd
from app.components.data_processor import export_issues_to_df
from app.components.IssuesTable import render_issues_table

def render_issues_list():
    """
    Renders a tabbed interface showing active and resolved issues.
    """
    tab1, tab2 = st.tabs(["Active Issues", "Resolved Issues"])

    def render_tab_content(status, label):
        df = export_issues_to_df(status=status)
        if not df.empty:
            render_issues_table(df)
            
            # Export button
            csv = df.to_csv(index=False)
            st.download_button(
                f"Export {label}",
                csv,
                f"{status}_findings.csv",
                "text/csv",
                key=f'download-{status}-csv'
            )
        else:
            st.info(f"No {label.lower()}.")

    with tab1:
        render_tab_content('open', 'Active Findings')

    with tab2:
        render_tab_content('resolved', 'Resolved Findings') 