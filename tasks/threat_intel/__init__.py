"""Threat-intelligence task registrations."""

from .core import (
    create_collection_task,
    create_correlation_task,
    create_enrichment_task,
    create_prediction_task,
    create_remediation_script_generation_task,
    create_remediation_task,
    create_tool_generation_task,
    create_vulnerability_scan_task,
)

__all__ = [
    "create_collection_task",
    "create_correlation_task",
    "create_enrichment_task",
    "create_prediction_task",
    "create_remediation_script_generation_task",
    "create_remediation_task",
    "create_tool_generation_task",
    "create_vulnerability_scan_task",
]
