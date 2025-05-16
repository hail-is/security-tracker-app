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

@click.group()
def cli():
    """Security findings management CLI."""
    pass

@cli.command()
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

@cli.command()
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

@cli.command()
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

@cli.command()
@click.argument('csv_file', type=click.Path(exists=True, path_type=Path))
def import_alerts(csv_file: Path):
    """
    Import Trivy alerts from a CSV file and display the first entry in YAML format.
    
    CSV_FILE: Path to the CSV file containing Trivy alerts
    """
    try:
        findings = import_alerts_from_csv(csv_file)
        if not findings:
            click.echo("No findings found in CSV file", err=True)
            sys.exit(1)
            
        # Get the first finding and convert to dict for YAML output
        first_finding = findings[0]
        finding_dict = {
            'finding_id': first_finding.finding_id,
            'controls': first_finding.controls,
            'weakness_name': first_finding.weakness_name,
            'weakness_description': first_finding.weakness_description,
            'weakness_detector_source': first_finding.weakness_detector_source,
            'weakness_source_identifier': first_finding.weakness_source_identifier,
            'asset_identifier': first_finding.asset_identifier,
            'point_of_contact': first_finding.point_of_contact,
            'resources_required': first_finding.resources_required,
            'overall_remediation_plan': first_finding.overall_remediation_plan,
            'original_detection_date': first_finding.original_detection_date.strftime("%Y-%m-%d"),
            'scheduled_completion_date': first_finding.scheduled_completion_date.strftime("%Y-%m-%d"),
            'planned_milestones': first_finding.planned_milestones,
            'milestone_changes': first_finding.milestone_changes,
            'status_date': first_finding.status_date.strftime("%Y-%m-%d"),
            'vendor_dependency': first_finding.vendor_dependency,
            'last_vendor_check_in_date': first_finding.last_vendor_check_in_date.strftime("%Y-%m-%d") if first_finding.last_vendor_check_in_date else None,
            'vendor_dependent_product_name': first_finding.vendor_dependent_product_name,
            'original_risk_rating': first_finding.original_risk_rating,
            'adjusted_risk_rating': first_finding.adjusted_risk_rating,
            'risk_adjustment': first_finding.risk_adjustment,
            'false_positive': first_finding.false_positive,
            'operational_requirement': first_finding.operational_requirement,
            'deviation_rationale': first_finding.deviation_rationale,
            'supporting_documents': first_finding.supporting_documents,
            'comments': first_finding.comments,
            'auto_approve': first_finding.auto_approve,
            'binding_operational_directive_22_01_tracking': first_finding.binding_operational_directive_22_01_tracking,
            'binding_operational_directive_22_01_due_date': first_finding.binding_operational_directive_22_01_due_date.strftime("%Y-%m-%d") if first_finding.binding_operational_directive_22_01_due_date else None,
            'cve': first_finding.cve,
            'service_name': first_finding.service_name
        }
        
        # Output as YAML
        click.echo(yaml.dump(finding_dict, sort_keys=False))
        
    except Exception as e:
        click.echo(f"Error importing alerts: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
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

@cli.command()
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
        raise e
        sys.exit(1)

if __name__ == '__main__':
    cli() 