import streamlit as st
from app.database.schema import get_db_connection, get_poam_config, update_poam_config

st.set_page_config(
    page_title="Settings",
    page_icon="🔒",
    layout="wide"
)

st.title("Settings")

# POAM Export Configuration
st.header("POAM Export Configuration")
st.write("Configure settings for POAM CSV exports.")

# Get current configuration
conn = get_db_connection()
config = get_poam_config(conn)

# Default values
point_of_contact = config['point_of_contact'] if config else ""
google_project = config['google_project'] if config else ""
service_name = config['service_name'] if config else ""

# Form for updating configuration
with st.form("poam_config_form"):
    new_point_of_contact = st.text_input(
        "Point of Contact",
        value=point_of_contact,
        help="The point of contact for POAM exports"
    )
    new_google_project = st.text_input(
        "Google Project",
        value=google_project,
        help="The Google project identifier"
    )
    new_service_name = st.text_input(
        "Service Name",
        value=service_name,
        help="The service name for POAM exports"
    )
    
    if st.form_submit_button("Save Configuration"):
        update_poam_config(
            conn,
            point_of_contact=new_point_of_contact,
            google_project=new_google_project,
            service_name=new_service_name
        )
        st.success("Configuration updated successfully!")

conn.close() 