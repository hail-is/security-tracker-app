"""
Module for handling CIS scan reports.
"""
from pathlib import Path
import pandas as pd
from datetime import datetime
import os

def split_connected_sheet(input_file: Path, output_dir: Path = None) -> list[Path]:
    """
    Split a CIS connected sheet Excel file into multiple CSV files by date.
    
    Args:
        input_file: Path to the input Excel file
        output_dir: Optional output directory. If None, uses input directory/Divided CIS Scans
        
    Returns:
        List of paths to the generated CSV files
        
    Notes:
        - Creates files in a "Divided CIS Scans" subdirectory
        - Names files as "<original_name> - YYYY-MM-DD.csv"
        - Preserves original row order
        - Skips writing if file for a date already exists
    """
    # Read the Excel file
    df = pd.read_excel(input_file)
    
    # Output directory is input directory with a "Divided CIS Scans" subdirectory
    if output_dir is None:
        output_dir = input_file.parent / "Divided CIS Scans"

    # Ensure output directory exists
    output_dir.mkdir(exist_ok=True)
    
    # Get base filename without "(Connected Sheet)" suffix
    base_name = input_file.stem

    # Remove "(Connected Sheet)" (and anything after it)
    if "(Connected Sheet)" in base_name:
        base_name = base_name.split("(Connected Sheet)")[0].strip()
    
    # Group by date and write separate files
    output_files = []
    for date, group in df.groupby("Date"):
        # Parse date and format filename
        try:
            # Try to parse date if it's not already a datetime
            if not isinstance(date, datetime):
                date = pd.to_datetime(date)
            date_str = date.strftime("%Y-%m-%d")
        except:
            # If date parsing fails, use the raw value
            date_str = str(date)
        
        # Generate output path
        output_file = output_dir / f"{base_name} - {date_str}.csv"
        
        # Skip if file already exists
        if not output_file.exists():
            # Sort by original index to preserve row order
            group = group.sort_index()
            
            # Write to CSV
            group.to_csv(output_file, index=False)
            output_files.append(output_file)
    
    return output_files 