"""Threat-intelligence agent registrations."""

from .core import (
    create_collection_agent,
    create_correlation_agent,
    create_enrichment_agent,
    create_prediction_agent,
    create_remediation_agent,
    create_remediation_script_generation_agent,
    create_reporting_agent,
    create_response_agent,
    create_tool_generation_agent,
    create_vulnerability_scan_agent,
)

__all__ = [
    "create_collection_agent",
    "create_correlation_agent",
    "create_enrichment_agent",
    "create_prediction_agent",
    "create_remediation_agent",
    "create_remediation_script_generation_agent",
    "create_reporting_agent",
    "create_response_agent",
    "create_tool_generation_agent",
    "create_vulnerability_scan_agent",
]
