# Security Findings Tracker

A CLI tool for tracking and managing POA&M (Plan of Action and Milestones) lifecycle for compliance purposes. Processes weekly security findings from Trivy, ZAP, and CIS scans and applies them to a POAM Excel file.

## Requirements

- Python 3.9 - 3.12
- Virtual environment (recommended)

## Features

- Download and process Trivy, ZAP, and CIS findings
- Diff findings against existing POAMs to identify new, closed, and reopened items
- Automatic due date assignment based on severity
- Apply diffs to update the POAM Excel file

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

