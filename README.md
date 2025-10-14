# Security Findings Tracker

A Streamlit-based application for tracking and managing security findings from weekly CSV uploads. The application provides an interface for analyzing security findings, tracking their status, and managing their lifecycle.

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
- Command line tools for automation and data management

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

## Command Line Tools

The application includes command line tools for automation and data management. These tools are available through the `cli.py` script in the `cli` directory.

### Command Groups

The CLI is organized into the following command groups:

1. `poams` - Commands for working with POAMs:
   ```bash
   # Interactive weekly update process
   ./cli/cli.py poams weekly-update
   
   # Preview Trivy POAMs from an Excel file
   ./cli/cli.py poams preview-trivy <file_path> [--limit <n>]
   
   # Apply diff changes to a POAM Excel file
   ./cli/cli.py poams apply-diff <poam_file> <diff_file>
   ```

2. `trivy` - Commands for working with Trivy:
   ```bash
   # Download Trivy alerts from GitHub code scanning API
   ./cli/cli.py trivy download-alerts [--destination <file_path>]
   
   # Convert GitHub Trivy alerts JSON to POAM CSV format
   ./cli/cli.py trivy convert-alerts <alerts_file> [--output <file_path>]
   
   # Compare Trivy alerts against existing POAMs
   ./cli/cli.py trivy alerts-diff <poam_file> <alerts_csv>
   ```

To see all available commands and their options:
```bash
./cli/cli.py --help
```

For help on a specific command group:
```bash
./cli/cli.py poams --help
./cli/cli.py trivy --help
```

### Authentication

The tools that interact with Google services use Application Default Credentials (ADC). To set up authentication:

1. Using gcloud (recommended for development):
```bash
gcloud auth application-default login
```

2. Or using a service account (recommended for production):
```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
```

### Available Commands

1. Download Google Sheets:
```bash
# Using a Google Sheets URL
./cli/cli.py download-gsheet "https://docs.google.com/spreadsheets/d/YOUR_SHEET_ID"

# Or using just the file ID
./cli/cli.py download-gsheet "YOUR_SHEET_ID"
```

The downloaded files will be saved to the `working` directory in the project root.

## Web Application Usage

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
