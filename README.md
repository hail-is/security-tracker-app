# Security Findings Tracker

A Streamlit-based application for tracking and managing security findings from weekly CSV uploads. The application provides a modern, intuitive interface for analyzing security findings, tracking their status, and managing their lifecycle.

## Requirements

- Python 3.9 - 3.12
- Virtual environment (recommended)

## Features

- Upload and process weekly CSV security findings
- Track new, existing, and resolved findings
- Automatic due date assignment based on severity
- Interactive data visualization
- Export capabilities for active and resolved findings
- Modern, responsive UI inspired by hail.is

## Installation

1. Ensure you have Python 3.9 or higher installed:
```bash
python --version  # Should show 3.9 or higher
```

2. Clone the repository:
```bash
git clone <repository-url>
cd security-tracker-app
```

3. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

4. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the Streamlit application (make sure you're in the repository root directory):
```bash
# On Unix/macOS:
PYTHONPATH=$PYTHONPATH:. streamlit run app/main.py

# On Windows (PowerShell):
$env:PYTHONPATH = "$env:PYTHONPATH;."
streamlit run app/main.py

# On Windows (Command Prompt):
set PYTHONPATH=%PYTHONPATH%;.
streamlit run app/main.py
```

2. Open your web browser and navigate to the URL shown in the terminal (typically http://localhost:8501)

3. Use the application:
   - Upload your weekly CSV file using the file uploader
   - Set the analysis date
   - View the summary statistics and visualizations
   - Track recurrances and resolutions through additional scans and uploads.
   - Export findings as needed

## Database

The application uses SQLite for data storage. The database file is created at `app/database/findings.db` and includes tables for:
- Findings tracking
- Upload history
