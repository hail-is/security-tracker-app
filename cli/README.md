# Security Findings CLI

Command-line interface for managing security findings from Trivy scans.

## Installation

Ensure you have Python 3.x installed and the required dependencies:

```bash
pip install -r requirements.txt
```

## Testing

To run the tests, first install pytest and coverage tools:

```bash
pip install pytest pytest-cov
```

The project uses a standard Python test layout:
```
security-tracker-app/
├── tests/
│   ├── __init__.py
│   ├── conftest.py      # Test configuration and fixtures
│   └── test_poam.py     # Tests for POAM functionality
├── tools/
│   ├── __init__.py
│   ├── poam.py
│   └── ...
└── cli/
    └── ...
```

Then run the tests:

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_poam.py

# Run with verbose output
pytest tests/test_poam.py -v

# Run tests and show coverage
pytest tests/ --cov=tools
```

The test suite includes:
- Unit tests for data conversion utilities
- Field name handling for POAM entries
- Edge cases for text formatting

## Commands

### Download Alerts

Download Trivy alerts from GitHub's code scanning API:

```bash
./cli.py download-alerts
```

This command:
- Downloads Trivy alerts from GitHub's code scanning API
- Saves them as a JSON file in the working directory
- Requires either:
  1. GitHub CLI (`gh`) installed and authenticated via `gh auth login`
  2. GitHub token provided via `GITHUB_TOKEN` environment variable

### Convert Alerts

Convert downloaded GitHub Trivy alerts from JSON to CSV format:

```bash
./cli.py convert-alerts <alerts_file>
```

This command:
- Takes a JSON file containing GitHub code scanning alerts
- Converts the alerts to a CSV format suitable for findings tracking
- Saves the output as a CSV file in the working directory

### Import and View Alerts

Import alerts from CSV and display the first entry in YAML format:

```bash
./cli.py import-alerts <csv_file>
```

This command:
- Reads a CSV file containing Trivy alerts
- Converts each row into a Finding object
- Displays the first finding in YAML format for review

### Compare Alerts with POAMs

Compare current Trivy alerts against existing POAMs:

```bash
./cli.py alerts-diff <poam_file> <alerts_csv>
```

This command:
- Reads existing POAMs from an Excel file
- Compares them against current findings from a CSV file
- Shows:
  - New findings that need POAMs created
  - Existing findings that already have POAMs (with confidence scores)
  - Closed POAMs that no longer have corresponding findings
- Matching is done based on:
  - Weakness name similarity
  - Asset identifier matching

### Preview Trivy POAMs

Preview POAMs from an Excel file:

```bash
./cli.py preview-trivy <file_path> [--limit <n>]
```

This command:
- Reads POAMs from an Excel file
- Displays a preview of the first n entries (default: 5)
- Requires an Excel file with an "Open POA&M Items" sheet and headers in row 5

## Example Workflow

1. Download alerts from GitHub:
   ```bash
   ./cli.py download-alerts
   ```

2. Convert the downloaded JSON to CSV:
   ```bash
   ./cli.py convert-alerts alerts_20240513.json
   ```

3. Compare new alerts against existing POAMs:
   ```bash
   ./cli.py alerts-diff existing_poams.xlsx working/trivy_alerts_20240513_180947.csv
   ```

4. Import and verify specific alerts:
   ```bash
   ./cli.py import-alerts working/trivy_alerts_20240513_180947.csv
   ```

Each command includes error handling and will provide helpful error messages if something goes wrong. 