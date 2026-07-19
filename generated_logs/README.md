# Generated SOC Tool Fixtures

These files are synthetic threat-intel/SOC evidence fixtures for local pipeline testing.
They are fake training data, not real incident telemetry.

- `soc_tool_bundle.json`: combined Wazuh, TheHive, MISP, and Cortex-style evidence. Use this with `crew_threat_intel.py`.
- `wazuh_alerts.json`: standalone Wazuh-style alert export.
- `thehive_case_export.json`: standalone TheHive-style case export.
- `misp_event_export.json`: standalone MISP-style event export.
- `cortex_analyzer_results.json`: standalone Cortex-style analyzer results.
- `joomla_cve_2023_23752_incident.json`: older generic generated-tool log bundle from the lab validation run.

Run the threat-intel pipeline with the combined SOC-tool bundle:

```bash
venv/bin/python crew_threat_intel.py 172.21.0.3 \
  --evidence-path generated_logs/soc_tool_bundle.json \
  --no-auto-remediation
```
