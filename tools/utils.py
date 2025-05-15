"""
Common utility functions used across tools.
"""
import os
from pathlib import Path

def ensure_working_dir() -> Path:
    """
    Ensure the working directory exists and return its path.
    The working directory is used for temporary files and downloads.
    
    Returns:
        Path object for the working directory
    """
    working_dir = Path(os.getcwd()) / 'working'
    working_dir.mkdir(exist_ok=True)
    return working_dir 