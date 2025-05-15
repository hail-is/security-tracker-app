"""
Tool for handling POAM Excel files.
"""
import pandas as pd
import re
import yaml
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

def convert_to_snake_case(text: str) -> str:
    """
    Convert a string to snake_case format.
    
    Args:
        text: Input string in any format (e.g., "Weakness Name", "POAM ID", etc.)
        
    Returns:
        String converted to snake_case format
    
    Examples:
        >>> convert_to_snake_case("Weakness Name")
        'weakness_name'
        >>> convert_to_snake_case("POAM ID")
        'poam_id'
        >>> convert_to_snake_case("Auto-Approve")
        'auto_approve'
    """
    if not text:
        return text
        
    # Replace hyphens with spaces
    text = text.replace('-', ' ')
    
    # Normalize spaces (remove extra spaces)
    text = ' '.join(text.split())
    
    # Convert to lowercase and replace spaces with underscores
    return text.strip().lower().replace(' ', '_')

@dataclass(frozen=True)
class PoamEntry:
    """Represents a single POAM entry."""
    poam_id: str
    controls: str
    weakness_name: str
    weakness_description: str
    weakness_detector_source: str
    weakness_source_identifier: str
    asset_identifier: str
    point_of_contact: str
    resources_required: Optional[str]
    overall_remediation_plan: str
    original_detection_date: datetime
    scheduled_completion_date: datetime
    planned_milestones: str
    milestone_changes: str
    status_date: datetime
    vendor_dependency: str
    last_vendor_check_in_date: Optional[datetime]
    vendor_dependent_product_name: str
    original_risk_rating: str
    adjusted_risk_rating: Optional[str]
    risk_adjustment: str
    false_positive: str
    operational_requirement: str
    deviation_rationale: Optional[str]
    supporting_documents: Optional[str]
    comments: Optional[str]
    auto_approve: str
    binding_operational_directive_22_01_tracking: str
    binding_operational_directive_22_01_due_date: Optional[datetime]
    cve: Optional[str]
    service_name: str

    def __hash__(self) -> int:
        """Make PoamEntry hashable based on its poam_id."""
        return hash(self.poam_id)

    def __eq__(self, other) -> bool:
        """Define equality based on poam_id."""
        if not isinstance(other, PoamEntry):
            return NotImplemented
        return self.poam_id == other.poam_id

    @classmethod
    def from_dict(cls, data: dict) -> 'PoamEntry':
        """Create a PoamEntry from a dictionary, handling timestamp conversion."""
        # Convert pandas timestamps to datetime
        date_fields = [
            'original_detection_date',
            'scheduled_completion_date',
            'status_date',
            'last_vendor_check_in_date',
            'binding_operational_directive_22_01_due_date'
        ]
        
        for field in date_fields:
            if field in data and pd.notna(data[field]):
                if isinstance(data[field], pd._libs.tslibs.timestamps.Timestamp):
                    data[field] = data[field].to_pydatetime()
            else:
                data[field] = None

        # Convert NaN to None for optional fields
        for key, value in data.items():
            if pd.isna(value):
                data[key] = None
            elif isinstance(value, float) and key != 'comments':  # Keep numeric comments
                data[key] = str(int(value)) if value.is_integer() else str(value)
            elif isinstance(value, str):
                data[key] = value.strip()

        # Rename POAM ID field if necessary
        if 'POAM ID' in data:
            data['poam_id'] = data.pop('POAM ID')

        # Convert keys to snake_case
        converted_data = {
            convert_to_snake_case(key): value 
            for key, value in data.items()
        }

        return cls(**converted_data)

class PoamFile:
    """Handler for POAM Excel files with specific support for Trivy findings."""
    
    def __init__(self, file_path: str):
        """
        Initialize a POAM file handler.
        
        Args:
            file_path: Path to the XLSX file
        """
        self.file_path = Path(file_path)
        if not self.file_path.exists():
            raise FileNotFoundError(f"POAM file not found: {file_path}")
        
        # Load the Excel file
        self.workbook = pd.ExcelFile(self.file_path)
        
        # Validate required sheet exists
        if "Open POA&M Items" not in self.workbook.sheet_names:
            raise ValueError('Excel file must contain "Open POA&M Items" sheet')
        
        # Load the open POAMs data with headers in row 5 (0-based index is 4)
        self.df = pd.read_excel(
            self.workbook,
            sheet_name="Open POA&M Items",
            header=4,  # 0-based index for row 5
            engine='openpyxl'
        )
        
        # Load closed POAMs if available
        self.closed_df = None
        if "Closed POA&M Items" in self.workbook.sheet_names:
            self.closed_df = pd.read_excel(
                self.workbook,
                sheet_name="Closed POA&M Items",
                header=4,  # 0-based index for row 5
                engine='openpyxl'
            )
    
    def get_trivy_poams(self) -> pd.DataFrame:
        """
        Filter and return Trivy POAMs.
        
        Returns:
            DataFrame containing only Trivy POAMs
        """
        # Pattern matches YYYY-TRIVYXXXX where XXXX is 4 or more digits
        trivy_pattern = r'^\d{4}-TRIVY\d{4,}$'
        
        # Filter for POAM IDs matching the Trivy pattern
        return self.df[self.df['POAM ID'].str.match(trivy_pattern, na=False)]
    
    def get_closed_trivy_poams(self) -> pd.DataFrame:
        """
        Filter and return closed Trivy POAMs.
        
        Returns:
            DataFrame containing only closed Trivy POAMs, or empty DataFrame if no closed POAMs exist
        """
        if self.closed_df is None:
            return pd.DataFrame()
            
        # Pattern matches YYYY-TRIVYXXXX where XXXX is 4 or more digits
        trivy_pattern = r'^\d{4}-TRIVY\d{4,}$'
        
        # Filter for POAM IDs matching the Trivy pattern
        return self.closed_df[self.closed_df['POAM ID'].str.match(trivy_pattern, na=False)]
    
    def get_trivy_poam_entries(self, limit: Optional[int] = None) -> tuple[list[PoamEntry], list[PoamEntry]]:
        """
        Get Trivy POAMs as PoamEntry objects.
        
        Args:
            limit: Optional number of entries to return
            
        Returns:
            Tuple of (open_poams, closed_poams) where each is a list of PoamEntry objects
        """
        # Get open POAMs
        open_df = self.get_trivy_poams()
        if limit:
            open_df = open_df.head(limit)
        open_poams = [PoamEntry.from_dict(row) for _, row in open_df.iterrows()]
        
        # Get closed POAMs
        closed_df = self.get_closed_trivy_poams()
        if limit:
            closed_df = closed_df.head(limit)
        closed_poams = [PoamEntry.from_dict(row) for _, row in closed_df.iterrows()]
        
        return open_poams, closed_poams
    
    def preview_trivy_poams(self, limit: int = 5) -> str:
        """
        Get a YAML preview of the first N Trivy POAMs.
        
        Args:
            limit: Number of POAMs to preview (default 5)
            
        Returns:
            YAML formatted string of the POAMs
        """
        open_entries, closed_entries = self.get_trivy_poam_entries(limit)
        
        # Convert to dict format expected in output
        preview_data = []
        for entry in open_entries:
            # Convert datetime objects to strings
            entry_dict = {}
            for field, value in entry.__dict__.items():
                if isinstance(value, datetime):
                    value = value.strftime('%Y-%m-%d')
                # Convert snake_case back to Title Case for keys
                key = ' '.join(word.capitalize() for word in field.split('_'))
                entry_dict[key] = value
            preview_data.append(entry_dict)
        
        # Convert to YAML with proper formatting
        return yaml.dump(preview_data, sort_keys=False, allow_unicode=True) 