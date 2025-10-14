"""
Common utility functions used across tools.
"""
import os
from pathlib import Path

def ensure_working_dir() -> Path:
    """
    Ensure the working directory exists and return its path.
    The working directory is used for temporary files and downloads.
    
    Checks for WORKING environment variable first, then falls back to pwd/working.
    
    Returns:
        Path object for the working directory
    """
    # Check WORKING environment variable first
    working_env = os.getenv('WORKING')
    if working_env:
        working_dir = Path(working_env)
    else:
        # Fall back to pwd/working
        working_dir = Path(os.getcwd()) / 'working'
    
    working_dir.mkdir(exist_ok=True)
    return working_dir 