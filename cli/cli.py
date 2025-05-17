#!/usr/bin/env python3

import json
import click
import sys
import os
from pathlib import Path
import yaml
from datetime import datetime

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.poam import PoamFile
from tools.github import download_trivy_alerts
from tools.trivy.alerts import convert_alerts_to_poam
from tools.trivy.importer import import_alerts_from_csv
from tools.trivy.diff import compare_findings_to_trivy_poams
from tools.trivy.diff_apply import apply_diff_from_files
from tools.zap import convert_alerts_to_findings

@click.group()
def cli():
    """Security tools CLI."""
    pass

@cli.group()
def poams():
    """Commands for working with POAMs."""
    pass

@cli.group()
def trivy():
    """Commands for working with Trivy."""
    pass

@cli.group()
def zap():
    """Commands for working with ZAP scan reports."""
    pass

@poams.command('preview-trivy')
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--limit', '-n', default=5, help='Number of POAMs to preview')
def preview_trivy(file_path, limit):
    """Preview Trivy POAMs from an Excel file.
    
    FILE_PATH should be the path to your POAM Excel file.
    The file must contain an "Open POA&M Items" sheet with headers in row 5.
    """
    try:
        poam_file = PoamFile(file_path)
        preview = poam_file.preview_trivy_poams(limit)
        click.echo(preview)
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@trivy.command('download-alerts')
def download_alerts():
    """Download Trivy alerts from GitHub code scanning API.
    
    REPO: Optional GitHub repository in owner/name format (e.g. 'owner/repo')
          If not provided, defaults to configured repository
    
    Requires one of:
    1. GitHub CLI (gh) to be installed and authenticated via 'gh auth login'
    2. GitHub token provided via --token option or GITHUB_TOKEN environment variable
    
    The alerts will be saved as a JSON file in the working directory.
    """
    try:
        output_file = download_trivy_alerts()
        click.echo(f"Successfully downloaded alerts to: {output_file}")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@trivy.command('convert-alerts')
@click.argument('alerts_file', type=click.Path(exists=True))
def convert_alerts(alerts_file):
    """Convert GitHub Trivy alerts JSON to POAM CSV format.
    
    ALERTS_FILE should be a JSON file containing GitHub code scanning alerts.
    The file can be obtained using the download-alerts command.
    
    The converted POAM data will be saved as a CSV file in the working directory.
    """
    try:
        alerts_path = Path(alerts_file)
        output_file = convert_alerts_to_poam(alerts_path)
        click.echo(f"Successfully converted alerts to POAM format: {output_file}")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@trivy.command('alerts-diff')
@click.argument('poam_file', type=click.Path(exists=True, path_type=Path))
@click.argument('alerts_csv', type=click.Path(exists=True, path_type=Path))
def alerts_diff(poam_file: Path, alerts_csv: Path):
    """
    Compare Trivy alerts from CSV against existing POAMs.
    
    POAM_FILE: Excel file containing existing POAMs
    ALERTS_CSV: CSV file containing current Trivy alerts
    
    Shows:
    - New findings that need POAMs created
    - Existing findings that already have POAMs
    - Closed POAMs that no longer have corresponding findings
    """
    try:
        # Import findings from CSV
        findings = import_alerts_from_csv(alerts_csv)
        if not findings:
            click.echo("No findings found in CSV file", err=True)
            sys.exit(1)
            
        # Compare findings against POAMs
        diff = compare_findings_to_trivy_poams(findings, poam_file)
        
        # Print results
        diff.print_summary()

        # JSON output file path:
        json_output_file = alerts_csv.with_suffix('.diff.json')
        with open(json_output_file, 'w') as f:
            json.dump(diff.to_json(), f)
        click.echo(f"JSON output saved to: {json_output_file}")
        
    except Exception as e:
        click.echo(f"Error comparing alerts: {str(e)}", err=True)
        sys.exit(1)

@poams.command('apply-diff')
@click.argument('poam_file', type=click.Path(exists=True, path_type=Path))
@click.argument('diff_file', type=click.Path(exists=True, path_type=Path))
def apply_diff(poam_file: Path, diff_file: Path) -> None:
    """Apply diff changes to a POAM Excel file.
    
    POAM_FILE: Excel file containing POAMs
    DIFF_FILE: JSON file containing diff changes
    
    This command will:
    - Add new POAMs to the Open POA&M Items sheet
    - Move reopened POAMs from Closed to Open sheet
    - Move closed POAMs from Open to Closed sheet
    """
    try:
        apply_diff_from_files(poam_file, diff_file)
        click.echo(f"Successfully applied diff changes to {poam_file}")
    except Exception as e:
        click.echo(f"Error applying diff: {str(e)}", err=True)
        sys.exit(1)

@zap.command('alerts-to-findings')
@click.argument('xml_file', type=click.Path(exists=True))
def alerts_to_findings(xml_file):
    """Convert ZAP XML alerts to findings JSON format.
    
    XML_FILE should be a ZAP XML report file.
    The findings will be saved as a JSON file and the first finding will be displayed.
    """
    try:
        # Convert alerts to findings
        output_file = convert_alerts_to_findings(xml_file)
        
        # Load and display first finding
        with open(output_file) as f:
            findings = json.load(f)
            if findings:
                click.echo("\nFirst finding from the report:")
                click.echo(json.dumps(findings[0], indent=2))
                click.echo(f"\nTotal findings: {len(findings)}")
                click.echo(f"All findings saved to: {output_file}")
            else:
                click.echo("No findings found in the report.")
    except Exception as e:
        click.echo(f"Error converting alerts: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli() 