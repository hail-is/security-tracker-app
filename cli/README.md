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

The CLI is organized into command groups for better organization and usability.

### POAM Commands

Commands for working with POAMs are grouped under the `poams` command:

```bash
# Preview POAMs from an Excel file
./cli.py poams preview-trivy <file_path> [--limit <n>]

# Apply diff changes to a POAM Excel file
./cli.py poams apply-diff <poam_file> <diff_file>
```

### Trivy Commands

Commands for working with Trivy alerts are grouped under the `trivy` command:

```bash
# Download Trivy alerts from GitHub's code scanning API
./cli.py trivy download-alerts

# Convert downloaded GitHub Trivy alerts from JSON to CSV format
./cli.py trivy convert-alerts <alerts_file>

# Compare current Trivy alerts against existing POAMs
./cli.py trivy alerts-diff <poam_file> <alerts_csv>
```

### ZAP Commands

Commands for working with ZAP scan reports are grouped under the `zap` command:

```bash
# Convert ZAP CSV alerts to findings JSON format
./cli.py zap alerts-to-findings <csv_file>
```

This command:
- Takes a ZAP CSV report file as input
- Converts each alert to a finding object with:
  - Finding ID (based on ZAP alert ID)
  - Weakness name and description
  - Asset identifier (host)
  - Risk rating and confidence level
  - List of affected instances (URLs, methods, parameters)
- Saves the findings as a JSON file
- Displays the first finding and total count

Each command includes error handling and will provide helpful error messages if something goes wrong.

## Example Workflow

1. Download alerts from GitHub:
   ```bash
   # Download to default location (WORKING env var or pwd/working)
   ./cli.py trivy download-alerts
   
   # Download to specific file
   ./cli.py trivy download-alerts --destination /path/to/alerts.json
   ```

2. Convert the downloaded JSON to CSV:
   ```bash
   # Convert with default .findings.csv extension in same directory
   ./cli.py trivy convert-alerts alerts_20240513.json
   
   # Convert to specific output file
   ./cli.py trivy convert-alerts alerts_20240513.json --output /path/to/output.csv
   ```

3. Compare new alerts against existing POAMs:
   ```bash
   ./cli.py trivy alerts-diff existing_poams.xlsx working/trivy_alerts_20240513_180947.csv
   ```

4. Preview POAMs in an Excel file:
   ```bash
   ./cli.py poams preview-trivy existing_poams.xlsx
   ```

5. Apply diff changes to update POAMs:
   ```bash
   # Apply single diff file
   ./cli.py poams apply-diff existing_poams.xlsx alerts_20240513.diff.json
   
   # Apply multiple diff files
   ./cli.py poams apply-diff existing_poams.xlsx alerts1.diff.json alerts2.diff.json alerts3.diff.json
   ```

   > [!NOTE]
   > We can merge the diff files before applying with `./cli.py poams merge-diffs` before applying, but the apply command also
   > accepts multiple diff files natively.
