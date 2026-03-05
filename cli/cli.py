#!/usr/bin/env python3

import json
import click
import sys
import os
import traceback
from pathlib import Path
from typing import Optional

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.findings import Finding
from tools.poam import PoamFile
from tools.github import download_trivy_alerts
from tools.trivy.alerts import convert_alerts_to_poam
from tools.trivy.importer import import_alerts_from_csv
from tools.trivy.diff import compare_findings_to_trivy_poams
from tools.diff_apply import apply_diff_from_files, merge_diffs
from tools.zap import convert_alerts_to_findings
from tools.zap.diff import compare_findings_to_zap_poams
from tools.cis.splitter import split_connected_sheet
from tools.cis.converter import convert_to_findings_file
from tools.cis.diff import compare_findings_to_cis_poams

def generate_alerts_diff(findings_file: Path, poams_file: Path, diff_file: Path, 
                        findings_loader, diff_generator, file_type: str) -> None:
    """Generate alerts diff for a findings file.
    
    Args:
        findings_file: Path to the findings file
        poams_file: Path to the POAMs file
        diff_file: Path where the diff file should be saved
        findings_loader: Function to load findings from the file
        diff_generator: Function to generate the diff
        file_type: Type of findings (for display purposes)
    
    Raises:
        FileNotFoundError: If findings file doesn't exist
    """
    if not findings_file.exists():
        raise FileNotFoundError(f"{file_type} findings file not found: {findings_file}")
    
    click.echo(f"> {file_type.lower()} alerts-diff {poams_file} {findings_file}")
    
    # Load findings
    all_findings = findings_loader(findings_file)
    if not all_findings:
        click.echo(f"No findings found in {file_type} file")
        return
    
    # Filter out Info severity findings
    findings = [f for f in all_findings if f.original_risk_rating.lower() != 'info']
    info_count = len(all_findings) - len(findings)
    
    if info_count > 0:
        click.echo(f"Excluded {info_count} findings with Info severity")
    
    if not findings:
        click.echo("No findings remaining after filtering out Info severity")
        return
    
    # Generate diff
    diff = diff_generator(findings, poams_file)
    
    # Print results
    diff.print_summary()
    
    # Save JSON output
    with open(diff_file, 'w') as f:
        json.dump(diff.to_json(), f, indent=2)
    click.echo(f"{file_type} diff saved to: {diff_file}")

def load_trivy_findings(csv_file: Path):
    """Load Trivy findings from CSV file."""
    return import_alerts_from_csv(csv_file)

def load_json_findings(json_file: Path):
    """Load findings from JSON file."""
    with open(json_file) as f:
        findings_data = json.load(f)
        return [Finding.from_dict(f) for f in findings_data]


def generate_updated_poam_filename(original_poam_file: str, today: str) -> str:
    """Generate updated POAM filename by replacing date in original filename with today's date.
    
    Args:
        original_poam_file: Original POAM file path
        today: Today's date in YYYY-MM-DD format
    
    Returns:
        Updated filename with today's date
    """
    from datetime import datetime
    import re
    
    # Try to find a date pattern in the filename (YYYY-MM-DD or YYYY_MM_DD)
    date_pattern = r'(\d{4}[-_]\d{2}[-_]\d{2})'
    match = re.search(date_pattern, original_poam_file)
    
    if match:
        # Replace the found date with today's date
        return re.sub(date_pattern, today, original_poam_file)
    else:
        # If no date found, insert today's date before the extension
        path = Path(original_poam_file)
        return str(path.parent / f"{path.stem} - {today}{path.suffix}")


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

@cli.group()
def cis():
    """Commands for working with CIS findings."""
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
@click.option('--destination', '-d', type=click.Path(), help='Destination file path for the alerts JSON file')
def download_alerts(destination):
    """Download Trivy alerts from GitHub code scanning API.
    
    If destination is not specified, uses WORKING environment variable or pwd/working
    and sets filename to trivy-alerts-<date>.json
    
    Requires the GitHub CLI (gh) to be installed and authenticated via 'gh auth login'.
    """
    try:
        if destination:
            # User provided a specific file path
            output_file = Path(destination)
            output_dir = output_file.parent
            output_file = download_trivy_alerts(output_dir)
            # Rename to the exact file the user requested
            if output_file.name != Path(destination).name:
                final_output = Path(destination)
                output_file.rename(final_output)
                output_file = final_output
        else:
            # Use default behavior with WORKING env var or pwd/working
            output_file = download_trivy_alerts()
        click.echo(f"Successfully downloaded alerts to: {output_file}")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)

@trivy.command('convert-alerts')
@click.argument('alerts_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file path (default: same directory as input with .findings.csv extension)')
def convert_alerts(alerts_file, output):
    """Convert GitHub Trivy alerts JSON to POAM CSV format.
    
    ALERTS_FILE should be a JSON file containing GitHub code scanning alerts.
    The file can be obtained using the download-alerts command.
    
    The converted POAM data will be saved as a CSV file with .findings.csv extension.
    """
    try:
        alerts_path = Path(alerts_file)
        output_path = Path(output) if output else None
        output_file = convert_alerts_to_poam(alerts_path, output_path)
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
    
    Note: Findings with Info severity are automatically excluded.
    """
    try:
        json_output_file = alerts_csv.with_suffix('.diff.json')
        generate_alerts_diff(
            alerts_csv,
            poam_file,
            json_output_file,
            load_trivy_findings,
            compare_findings_to_trivy_poams,
            "Trivy"
        )
    except Exception as e:
        click.echo(f"Error comparing alerts: {str(e)}", err=True)
        sys.exit(1)

@poams.command('apply-diff')
@click.argument('poam_file', type=click.Path(exists=True, path_type=Path))
@click.argument('diff_files', nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file path (default: creates timestamped backup)')
def apply_diff(poam_file: Path, diff_files: tuple, output: Optional[Path]) -> None:
    """Apply diff changes to a POAM Excel file.
    
    POAM_FILE: Excel file containing POAMs
    DIFF_FILES: One or more JSON files containing diff changes
    
    This command will:
    - Add new POAMs to the Open POA&M Items sheet
    - Move reopened POAMs from Closed to Open sheet
    - Move closed POAMs from Open to Closed sheet
    
    If multiple diff files are provided, they will be merged before applying.
    If --output is specified, the updated file will be saved to that location.
    Otherwise, a default name will be used.
    """
    try:
        if not diff_files:
            click.echo("Error: At least one diff file must be provided", err=True)
            sys.exit(1)

        result = apply_diff_from_files(poam_file, list(diff_files), output)
        click.echo(f"Successfully applied diff changes to {result}")
    except Exception as e:
        click.echo(f"Error applying diff: {str(e)}", err=True)
        click.echo("\nFull traceback:", err=True)
        click.echo(traceback.format_exc(), err=True)
        sys.exit(1)

@poams.command('merge-diffs')
@click.argument('diff_files', nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file path (default: merged_diff.json)')
def merge_diffs_cmd(diff_files: tuple, output: Optional[Path]) -> None:
    """Merge multiple diff JSON files into a single diff file.
    
    DIFF_FILES: One or more JSON diff files to merge
    --output: Output file path (default: merged_diff.json)
    
    This command combines all the changes from multiple diff files into a single
    diff file that can be applied to a POAM Excel file.
    """
    try:
        if not diff_files:
            click.echo("Error: At least one diff file must be provided", err=True)
            sys.exit(1)
        
        if not output:
            output = Path("merged_diff.json")
        
        merged_diff = merge_diffs(list(diff_files))
        
        with open(output, 'w') as f:
            json.dump(merged_diff, f, indent=2)
        
        click.echo(f"Successfully merged {len(diff_files)} diff files into {output}")
        
        # Print summary of merged content
        total_new = len(merged_diff.get("new_poams", []))
        total_reopen = len(merged_diff.get("reopen_poams", []))
        total_close = len(merged_diff.get("close_poams", []))
        total_config_new = len(merged_diff.get("proposed_configuration_findings", []))
        total_config_close = len(merged_diff.get("closed_configuration_findings", []))
        
        click.echo(f"Merged content:")
        click.echo(f"  - New POAMs: {total_new}")
        click.echo(f"  - Reopen POAMs: {total_reopen}")
        click.echo(f"  - Close POAMs: {total_close}")
        click.echo(f"  - New Configuration Findings: {total_config_new}")
        click.echo(f"  - Close Configuration Findings: {total_config_close}")
        
    except Exception as e:
        click.echo(f"Error merging diffs: {str(e)}", err=True)
        click.echo("\nFull traceback:", err=True)
        click.echo(traceback.format_exc(), err=True)
        sys.exit(1)

@poams.command('weekly-update')
def weekly_update():
    """Interactive weekly update process for POAMs.
    
    This command guides you through the weekly update process including:
    - Setting up working directory
    - Processing Trivy alerts
    - Processing CIS findings
    - Processing ZAP scans
    """
    from datetime import datetime
    
    try:
        # 1. Prompt for working directory
        today = datetime.now().strftime("%Y-%m-%d")
        default_working_dir = f"working/{today}"
        working_dir = click.prompt("Working directory", default=default_working_dir)
        working_path = Path(working_dir)
        working_path.mkdir(parents=True, exist_ok=True)
        
        # 2. Print current directory contents
        click.echo(f"\nCurrent directory contents:")
        items = list(sorted(working_path.iterdir()))
        if len(items) > 0:
            for item in items:
                click.echo(f"  {item}")
        else:
            click.echo("  (empty)")
        
        # 3. Ask for input file paths
        click.echo(f"\n--- Input Files ---")
        
        # Find files in working directory
        cis_files = list(working_path.glob("*CIS*.xlsx"))
        hail_files = list(working_path.glob("hail_report*.csv"))
        poam_files = list(working_path.glob("*POAM*.xlsx"))
        
        # Use the first found file or empty string if none found
        cis_default = str(cis_files[0]) if cis_files else ""
        zap_default = str(hail_files[0]) if hail_files else ""
        poams_default = str(poam_files[0]) if poam_files else ""

        cis_findings = click.prompt("Path to continuous CIS findings sheet", default=cis_default)
        zap_scan = click.prompt("Path to most recent ZAP scan", default=zap_default)
        poams_file = click.prompt("Path to current POAMs file", default=poams_default)
        
        # 4. Trivy actions
        click.echo(f"\n--- Trivy Actions ---")
        trivy_alerts_file = working_path / f"trivy-alerts-{today}.json"
        trivy_findings_file = working_path / f"trivy-findings-{today}.findings.csv"
        
        skip_trivy = False
        if trivy_findings_file.exists():
            skip_trivy = click.confirm(f"Trivy findings file {trivy_findings_file} already exists. Skip Trivy actions?", default=True)
        
        if not skip_trivy:
            if click.confirm(f"Download Trivy alerts to {trivy_alerts_file}?", default=True, abort=True):
                click.echo(f"> trivy download-alerts -d {trivy_alerts_file}")
                download_trivy_alerts(trivy_alerts_file.parent)
                # Rename to the exact file we want
                if trivy_alerts_file.exists():
                    trivy_alerts_file.unlink()  # Remove if it exists with different name
                # Find the actual downloaded file and rename it
                for file in working_path.glob("trivy_alerts_*.json"):
                    file.rename(trivy_alerts_file)
                    break
            
            if click.confirm(f"Convert Trivy alerts to findings CSV?", default=True, abort=True):
                click.echo(f"> trivy convert-alerts {trivy_alerts_file} -o {trivy_findings_file}")
                convert_alerts_to_poam(trivy_alerts_file, trivy_findings_file)
        
        # 5. CIS actions
        click.echo(f"\n--- CIS Actions ---")
        split_output_dir = working_path / "Divided CIS Scans"
        cis_findings_file = working_path / f"cis-findings-{today}.findings.json"
        
        skip_cis = False
        if cis_findings_file.exists():
            skip_cis = click.confirm(f"CIS findings file {cis_findings_file} already exists. Skip CIS actions?", default=True)
        
        if not skip_cis:
            if click.confirm(f"Split CIS connected sheet?", default=True, abort=True):
                click.echo(f"> cis split-connected-sheet {cis_findings} -o {split_output_dir}")
                split_connected_sheet(Path(cis_findings), split_output_dir)
                
                # Find the most recent findings file (sort by filename since filenames include the date in YYYY-MM-DD format and are otherwise the same)
                if split_output_dir.exists():
                    csv_files = list(split_output_dir.glob("*.csv"))
                    if csv_files:
                        most_recent_file = max(csv_files, key=lambda f: f.name)
                        click.echo(f"Most recent findings file: {most_recent_file}")
                        
                        if click.confirm(f"Convert CIS CSV to findings?", default=True, abort=True):
                            click.echo(f"> cis csv-to-findings {most_recent_file} -o {cis_findings_file}")
                            convert_to_findings_file(most_recent_file, cis_findings_file)
        
        # 6. ZAP actions
        click.echo(f"\n--- ZAP Actions ---")
        zap_findings_file = working_path / f"zap-findings-{today}.findings.json"
        
        skip_zap = False
        if zap_findings_file.exists():
            skip_zap = click.confirm(f"ZAP findings file {zap_findings_file} already exists. Skip ZAP actions?", default=True)
        
        if not skip_zap:
            if click.confirm(f"Convert ZAP scan to findings?", default=True, abort=True):
                click.echo(f"> zap alerts-to-findings {zap_scan} -o {zap_findings_file}")
                convert_alerts_to_findings(zap_scan, str(zap_findings_file))
        
        # 7. Generate alerts-diffs
        click.echo(f"\n--- Generate Alerts Diffs ---")
        
        # Trivy alerts diff
        trivy_diff_file = trivy_findings_file.with_suffix('.diff.json')
        skip_trivy_diff = False
        if trivy_diff_file.exists():
            skip_trivy_diff = click.confirm(f"Trivy diff file {trivy_diff_file} already exists. Skip Trivy diff generation?", default=True)
        
        if not skip_trivy_diff:
            if click.confirm(f"Generate Trivy alerts diff?", default=True, abort=True):
                generate_alerts_diff(
                    trivy_findings_file, 
                    Path(poams_file), 
                    trivy_diff_file,
                    load_trivy_findings,
                    compare_findings_to_trivy_poams,
                    "Trivy"
                )
        
        # CIS alerts diff
        cis_diff_file = cis_findings_file.with_suffix('.diff.json')
        skip_cis_diff = False
        if cis_diff_file.exists():
            skip_cis_diff = click.confirm(f"CIS diff file {cis_diff_file} already exists. Skip CIS diff generation?", default=True)
        
        if not skip_cis_diff:
            if click.confirm(f"Generate CIS alerts diff?", default=True, abort=True):
                generate_alerts_diff(
                    cis_findings_file, 
                    Path(poams_file), 
                    cis_diff_file,
                    load_json_findings,
                    compare_findings_to_cis_poams,
                    "CIS"
                )
        
        # ZAP alerts diff
        zap_diff_file = zap_findings_file.with_suffix('.diff.json')
        skip_zap_diff = False
        if zap_diff_file.exists():
            skip_zap_diff = click.confirm(f"ZAP diff file {zap_diff_file} already exists. Skip ZAP diff generation?", default=True)
        
        if not skip_zap_diff:
            if click.confirm(f"Generate ZAP alerts diff?", default=True, abort=True):
                generate_alerts_diff(
                    zap_findings_file, 
                    Path(poams_file), 
                    zap_diff_file,
                    load_json_findings,
                    compare_findings_to_zap_poams,
                    "ZAP"
                )

        # 8. Apply diffs
        click.echo(f"\n--- Apply Diffs ---")
        
        # Generate updated POAM filename
        updated_poam_file = generate_updated_poam_filename(poams_file, today)
        updated_poam_path = Path(updated_poam_file)
        
        skip_apply_diffs = False
        if updated_poam_path.exists():
            skip_apply_diffs = click.confirm(f"Updated POAM file {updated_poam_path} already exists. Skip applying diffs?", default=True)
        
        if not skip_apply_diffs:
            if click.confirm(f"Apply diffs to create updated POAMs?", default=True, abort=True):
                diff_files = [trivy_diff_file, cis_diff_file, zap_diff_file]
                
                click.echo(f"> poams apply-diff {poams_file} {' '.join(str(f) for f in diff_files)} -o {updated_poam_path}")
    
                # Apply the diffs
                result = apply_diff_from_files(poams_file, diff_files, updated_poam_path)
                click.echo(f"Successfully applied diff changes to {result}")

        click.echo(f"\n--- Weekly Update Complete ---")
        click.echo(f"Working directory: {working_path}")
        click.echo(f"Output files to upload:")
        click.echo(f"  trivy findings: {trivy_findings_file}")
        click.echo(f"  cis findings: {cis_findings_file}")
        click.echo(f"  zap findings: {zap_findings_file}")
        click.echo(f"  updated POAMs: {result}")
        
    except Exception as e:
        click.echo(f"Error during weekly update: {str(e)}", err=True)
        click.echo(traceback.format_exc(), err=True)
        sys.exit(1)

@zap.command('alerts-to-findings')
@click.argument('csv_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file path (default: input file with .findings.json extension)')
def alerts_to_findings(csv_file, output):
    """Convert ZAP CSV alerts to findings JSON format.
    
    CSV_FILE should be a ZAP CSV report file.
    The findings will be saved as a JSON file and the first finding will be displayed.
    """
    try:
        # Convert alerts to findings
        output_file = convert_alerts_to_findings(csv_file, output)
        
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

@zap.command('alerts-diff')
@click.argument('poam_file', type=click.Path(exists=True))
@click.argument('findings_file', type=click.Path(exists=True))
@click.option('--json-output', type=click.Path(), help='Path to save JSON output')
def zap_alerts_diff(poam_file: str, findings_file: str, json_output: Optional[str]) -> None:
    """Compare ZAP findings against existing POAMs.
    
    Note: Findings with Info severity are automatically excluded.
    """
    try:
        if not json_output:
            findings_path = Path(findings_file)
            json_output = findings_path.with_suffix('.diff.json')
        
        generate_alerts_diff(
            Path(findings_file),
            Path(poam_file),
            Path(json_output),
            load_json_findings,
            compare_findings_to_zap_poams,
            "ZAP"
        )
    except Exception as e:
        click.echo(f"Error comparing findings: {str(e)}", err=True)
        sys.exit(1)

@cis.command('split-connected-sheet')
@click.argument('xlsx_file', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output directory for split CSV files (default: input directory/Divided CIS Scans)')
def split_connected_sheet_cmd(xlsx_file: Path, output: Optional[Path]) -> None:
    """Split a CIS connected sheet into separate CSV files by date.
    
    XLSX_FILE should be a CIS connected sheet Excel file.
    
    The command will:
    - Create a "Divided CIS Scans" directory if it doesn't exist
    - Split the file into multiple CSVs based on the Date field
    - Name each file as "<original_name> - YYYY-MM-DD.csv"
    - Skip writing if a file for a particular date already exists
    """
    try:
        output_files = split_connected_sheet(xlsx_file, output)
        if output_files:
            click.echo(f"Successfully split {xlsx_file.name} into {len(output_files)} files:")
            for f in output_files:
                click.echo(f"  - {f.name}")
        else:
            click.echo("No new files created (all dates already exist)")
    except Exception as e:
        click.echo(f"Error splitting connected sheet: {str(e)}", err=True)
        sys.exit(1)

@cis.command('csv-to-findings')
@click.argument('csv_file', type=click.Path(exists=True, path_type=Path))
@click.option('--output', '-o', type=click.Path(path_type=Path), help='Output file path (default: input file with .findings.json extension)')
def csv_to_findings_cmd(csv_file: Path, output: Optional[Path]) -> None:
    """Convert a CIS CSV file to findings JSON format.
    
    CSV_FILE should be a CIS CSV file (typically from split-connected-sheet).
    
    The command will:
    - Convert each row into one or more findings based on the Failures field
    - Generate finding IDs in the format CIS-<CIS_ID>-XXXX
    - Save the findings as <input_file>.findings.json
    """
    try:
        output_file = convert_to_findings_file(csv_file, output)
        
        # Load and display summary
        with open(output_file) as f:
            findings = json.load(f)
            click.echo(f"\nSuccessfully converted {csv_file.name} to findings:")
            click.echo(f"- Total findings: {len(findings)}")
            if findings:
                unique_rules = len({f['weakness_name'] for f in findings})
                click.echo(f"- Unique CIS rules: {unique_rules}")
                click.echo("\nSample finding:")
                click.echo(json.dumps(findings[0], indent=2))
            click.echo(f"\nOutput saved to: {output_file}")
    except Exception as e:
        click.echo(f"Error converting CSV to findings: {str(e)}", err=True)
        sys.exit(1)

@cis.command('alerts-diff')
@click.argument('poam_file', type=click.Path(exists=True))
@click.argument('findings_file', type=click.Path(exists=True))
@click.option('--json-output', type=click.Path(), help='Path to save JSON output')
def cis_alerts_diff(poam_file: str, findings_file: str, json_output: Optional[str]) -> None:
    """
    Compare CIS findings against existing configuration findings.
    
    FINDINGS_FILE: JSON file containing CIS findings
    POAM_FILE: Excel file containing configuration findings
    
    Note: Findings with Info severity are automatically excluded.
    """
    try:
        if not json_output:
            findings_path = Path(findings_file)
            json_output = findings_path.with_suffix('.diff.json')
        
        generate_alerts_diff(
            Path(findings_file),
            Path(poam_file),
            Path(json_output),
            load_json_findings,
            compare_findings_to_cis_poams,
            "CIS"
        )
    except Exception as e:
        click.echo(f"Error comparing findings: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli() 