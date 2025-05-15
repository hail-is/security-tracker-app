"""
Tool for interacting with GitHub APIs.
"""
import json
import subprocess
from datetime import datetime
from pathlib import Path

from .utils import ensure_working_dir

def download_trivy_alerts() -> Path:
    """
    Download Trivy alerts from GitHub code scanning API.
    Uses gh CLI tool to handle authentication and pagination.
    
    Returns:
        Path to the downloaded JSON file
    """
    working_dir = ensure_working_dir()
    
    # Generate timestamp for the filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = working_dir / f"trivy_alerts_{timestamp}.json"
    
    try:
        # Run gh command and capture output
        cmd = [
            "gh", "api", "--paginate",
            "-X", "GET",
            "/repos/hail-is/hail/code-scanning/alerts",
            "-f", "q=branch:main tool:Trivy"
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse and save the JSON response
        alerts = json.loads(result.stdout)
        output_file.write_text(json.dumps(alerts, indent=2))
            
        return output_file
        
    except subprocess.CalledProcessError as e:
        raise Exception(
            f"Failed to download alerts. Make sure:\n"
            f"1. The gh CLI tool is installed\n"
            f"2. You are authenticated with gh auth login\n"
            f"3. You have access to the hail-is/hail repository\n"
            f"\nError: {e.stderr}"
        )
    except json.JSONDecodeError as e:
        raise Exception(f"Failed to parse GitHub API response: {e}")
    except Exception as e:
        raise Exception(f"Unexpected error downloading alerts: {e}") 
