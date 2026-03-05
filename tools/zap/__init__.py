"""
Package for handling ZAP scan reports and findings.
"""

from .alerts import convert_alerts_to_findings

__all__ = ['convert_alerts_to_findings'] 