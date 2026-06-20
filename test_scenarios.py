"""
Test scenarios for the Healthcare AI Cybersecurity Threat Intelligence System.

Runs three defensive analysis queries and prints the results.
"""
import os
import textwrap
from dotenv import load_dotenv

# Load environment variables BEFORE importing agents
load_dotenv()

from agents import CTIAnalystAgent, AttributionAgent, DetectionAgent


def print_banner(title: str):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def print_response(response: str):
    print("-" * 70)
    # Wrap long lines for readability
    for line in response.splitlines():
        if len(line) > 100:
            print(textwrap.fill(line, width=100))
        else:
            print(line)


def main():
    print("Initializing Agents...\n")
    cti_agent = CTIAnalystAgent()
    detection_agent = DetectionAgent()
    attribution_agent = AttributionAgent()

    # ------------------------------------------------------------------
    # Scenario 1: Threat Intelligence — Ryuk lifecycle
    # ------------------------------------------------------------------
    print_banner("Scenario 1: Threat Intelligence — Ryuk Ransomware Lifecycle")
    query_1 = (
        "Describe the typical attack lifecycle of Ryuk ransomware against a hospital, "
        "mapping each stage to MITRE ATT&CK tactics and techniques."
    )
    print(f"Query: {query_1}")
    print_response(cti_agent.analyze(query_1))

    # ------------------------------------------------------------------
    # Scenario 2: Detection Engineering — MFA fatigue
    # ------------------------------------------------------------------
    print_banner("Scenario 2: Detection Engineering — MFA Fatigue Detection")
    query_2 = (
        "What SIEM rules, detection analytics, and mitigations can detect or prevent "
        "MFA fatigue attacks against hospital portals? Include specific data sources "
        "and log fields to monitor."
    )
    print(f"Query: {query_2}")
    print_response(detection_agent.detect(query_2))

    # ------------------------------------------------------------------
    # Scenario 3: Attribution — Wizard Spider
    # ------------------------------------------------------------------
    print_banner("Scenario 3: Attribution — Wizard Spider / Ryuk Threat Actor")
    query_3 = (
        "What threat actor group is associated with Ryuk ransomware? "
        "List their known TTPs and tools."
    )
    print(f"Query: {query_3}")
    print_response(attribution_agent.attribute(query_3))

    # ------------------------------------------------------------------
    # Scenario 4: Hallucination Check — T9999
    # ------------------------------------------------------------------
    print_banner("Scenario 4: Hallucination Check — T9999")
    query_4 = "What is T9999?"
    print(f"Query: {query_4}")
    print_response(cti_agent.analyze(query_4))


if __name__ == "__main__":
    main()
