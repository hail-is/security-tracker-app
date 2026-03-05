# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A security findings tracker that manages POA&M (Plan of Action and Milestones) lifecycle for compliance purposes. The CLI (`cli/cli.py`) is the sole entry point.

## Commands

### Setup
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### CLI Usage
```bash
./cli/cli.py --help
./cli/cli.py poams weekly-update          # Interactive guided weekly update
./cli/cli.py poams apply-diff <poam.xlsx> <diff.json> [<diff2.json> ...]
./cli/cli.py poams merge-diffs <diff1.json> <diff2.json> -o merged.json
./cli/cli.py trivy download-alerts [-d <dest>]
./cli/cli.py trivy convert-alerts <alerts.json> [-o <output.csv>]
./cli/cli.py trivy alerts-diff <poam.xlsx> <alerts.csv>
./cli/cli.py zap alerts-to-findings <report.csv> [-o <output.json>]
./cli/cli.py zap alerts-diff <poam.xlsx> <findings.json>
./cli/cli.py cis split-connected-sheet <file.xlsx> [-o <output_dir>]
./cli/cli.py cis csv-to-findings <file.csv> [-o <output.json>]
./cli/cli.py cis alerts-diff <poam.xlsx> <findings.json>
```

### Tests
```bash
python -m pytest                          # Run all tests
python -m pytest tests/test_diff.py      # Run a single test file
python -m pytest tests/test_diff.py::test_name  # Run a single test
```

## Architecture

### Data Flow (weekly update)
1. **Download/collect** raw scan data: Trivy alerts from GitHub API, CIS Excel sheet, ZAP CSV report
2. **Convert** to normalized intermediate formats: `.findings.csv` (Trivy) or `.findings.json` (CIS, ZAP)
3. **Diff** each findings file against the existing POAM Excel → produces `.diff.json` files
4. **Apply** one or more diff JSONs to create an updated POAM Excel file

### Core Data Structures (`tools/`)
- `tools/findings.py` — `Finding` dataclass: source-agnostic normalized security finding
- `tools/poam.py` — `PoamEntry` dataclass + `PoamFile` class: reads POAM Excel files (headers on row 5 of "Open POA&M Items" / "Closed POA&M Items" sheets)
- `tools/diff.py` — `compare_findings_to_poams()` and `PoamFileDiff`: matches findings to POAMs by exact `weakness_name` + asset coverage; produces lists of new/existing/closed/reopened
- `tools/diff_apply.py` — `apply_diff()`: writes changes back to Excel using openpyxl

### Source-Specific Modules
Each scanner type (`trivy/`, `zap/`, `cis/`) has:
- `alerts.py` or `converter.py` — converts raw scanner output to `Finding` objects
- `diff.py` — calls `compare_findings_to_poams()` with the right POAM filter and generator
- `poam_generator.py` — generates `PoamEntry` objects with appropriate POAM IDs

POAM ID formats: Trivy → `YYYY-TRIVYXXXX`, CIS → `CIS-<CIS_ID>-XXXX`

### Working Directory Convention
By default, files are saved to `working/YYYY-MM-DD/`. The `WORKING` environment variable can override the base path.

### Authentication
- GitHub (for Trivy downloads): `gh auth login` or `GITHUB_TOKEN` env var
- Google services: `gcloud auth application-default login` or `GOOGLE_APPLICATION_CREDENTIALS` env var
