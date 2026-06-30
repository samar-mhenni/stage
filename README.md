# CrewAI SOC Threat Intelligence

Focused CrewAI workflow for authorized Metasploitable lab analysis.

The supported path is:

1. `nmap_scan_agent` runs Nmap service discovery with `NmapTool`.
2. `vulnerability_scan_agent` analyzes the scan with `VulnerabilityScanTool`, ExploitDB, and the knowledge base.
3. `reporting_agent` writes the SOC threat-intelligence report.
4. `remediation_agent` writes concrete defensive correction steps.
5. The full result is saved to SQLite in `outputs/threat_intel_results.db`.

The existing LLM and vector settings are preserved in `config/settings.py`:

- `OPENROUTER_API_KEY`
- `OPENROUTER_BASE_URL`
- `QWEN_MODEL`
- `CHROMADB_PATH`

## Install

```bash
pip install -r requirements.txt
```

## Run

Default target is the existing Metasploitable lab address `172.17.0.2`.

```bash
python crew_threat_intel.py
```

Use a custom target:

```bash
python crew_threat_intel.py 172.17.0.2 --ports 1-10000 --timeout 180
```

Reuse an existing scan JSON instead of scanning:

```bash
python crew_threat_intel.py 172.17.0.2 --reuse-scan path/to/scan.json
```

## API

Start the API:

```bash
uvicorn api:app --host 127.0.0.1 --port 8000
```

Run the pipeline:

```bash
curl -s -X POST http://127.0.0.1:8000/api/threat-intel/run \
  -H "Content-Type: application/json" \
  -d '{"target":"172.17.0.2","ports":"1-10000","timeout":180}' | python -m json.tool
```

List saved runs:

```bash
curl -s http://127.0.0.1:8000/api/threat-intel/runs | python -m json.tool
```

Fetch a run:

```bash
curl -s http://127.0.0.1:8000/api/threat-intel/runs/1 | python -m json.tool
```

## Output

Results are stored in:

```text
outputs/threat_intel_results.db
```

Each run also writes old-style file artifacts:

```text
outputs/runs/run_0001/threat_intel_output.md
outputs/runs/run_0001/nmap_scan.json
outputs/runs/run_0001/service_summary.txt
outputs/runs/run_0001/vulnerability_report.md
outputs/runs/run_0001/soc_report.md
outputs/runs/run_0001/remediation_plan.md
outputs/runs/run_0001/nmap_agent_output.txt
```

Table:

```text
threat_intel_runs
```

The table includes target, ports, raw scan JSON, service summary, threat-intel enrichment, and the final SOC report.
