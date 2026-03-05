"""
Module for handling security findings data structures.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
import pandas as pd

@dataclass
class Finding:
    """Represents a single security finding."""
    finding_id: str
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

    @classmethod
    def from_dict(cls, data: dict) -> 'Finding':
        """Create a Finding from a dictionary, handling timestamp conversion."""
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

        # Rename ID field if necessary
        if 'POAM ID' in data:
            data['finding_id'] = data.pop('POAM ID')
        elif 'Alert ID' in data:
            data['finding_id'] = data.pop('Alert ID')

        # Convert keys to snake_case
        converted_data = {}
        for key, value in data.items():
            snake_key = ''.join(['_' + c.lower() if c.isupper() else c.lower() for c in key]).lstrip('_')
            converted_data[snake_key] = value

        return cls(**converted_data) 