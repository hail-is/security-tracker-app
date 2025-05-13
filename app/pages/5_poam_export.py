import streamlit as st
from app.components.poam_exports import generate_poam_export
from app.database.schema import get_db_connection, get_poam_config
from datetime import datetime

st.set_page_config(
    page_title="POAM Export",
    page_icon="🔒",
    layout="wide"
)

st.title("POAM Export")

# Check if POAM configuration exists
conn = get_db_connection()
config = get_poam_config(conn)
conn.close()

if not config:
    st.error("POAM configuration is not set. Please configure POAM export settings in the Settings page first.")
    st.stop()

# Display current configuration
st.write("Current POAM Configuration:")
st.json({
    "Point of Contact": config['point_of_contact'],
    "Google Project": config['google_project'],
    "Service Name": config['service_name']
})

st.divider()

# Export buttons for open and closed issues
col1, col2 = st.columns(2)

with col1:
    st.subheader("Export Open Issues")
    if st.button("Download Open Issues POAM", type="primary"):
        try:
            df = generate_poam_export(status='open')
            if df.empty:
                st.warning("No open issues found.")
            else:
                # Generate CSV
                csv = df.to_csv(index=False)
                current_date = datetime.now().strftime('%Y%m%d')
                filename = f"poam_open_issues_{current_date}.csv"
                
                # Create download button
                st.download_button(
                    label="Click to Download Open Issues POAM",
                    data=csv,
                    file_name=filename,
                    mime="text/csv"
                )
                st.success(f"Generated POAM export with {len(df)} open issues.")
        except Exception as e:
            st.error(f"Error generating POAM export: {str(e)}")

with col2:
    st.subheader("Export Closed Issues")
    if st.button("Download Closed Issues POAM", type="primary"):
        try:
            df = generate_poam_export(status='resolved')
            if df.empty:
                st.warning("No closed issues found.")
            else:
                # Generate CSV
                csv = df.to_csv(index=False)
                current_date = datetime.now().strftime('%Y%m%d')
                filename = f"poam_closed_issues_{current_date}.csv"
                
                # Create download button
                st.download_button(
                    label="Click to Download Closed Issues POAM",
                    data=csv,
                    file_name=filename,
                    mime="text/csv"
                )
                st.success(f"Generated POAM export with {len(df)} closed issues.")
        except Exception as e:
            st.error(f"Error generating POAM export: {str(e)}")

# Add help text
st.divider()
st.markdown("""
### About POAM Export
This page allows you to export security issues in Plan of Action and Milestones (POAM) format. The export includes:

- Separate exports for open and closed issues
- POAM IDs in the format YYYY-CISxxxx (based on issue creation year)
- Standard CIS control mapping (CM-6)
- Configured point of contact and project information
- Detailed finding information including:
  - Weakness details and descriptions
  - Asset identifiers
  - Detection and due dates
  - Risk ratings based on CVSS scores
""") 