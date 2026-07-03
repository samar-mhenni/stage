# CrewAI SOC Threat Intelligence

Focused CrewAI workflow for authorized Metasploitable lab analysis.

The supported threat-intel crew path is:

1. `collection_agent` collects authorized service and telemetry evidence.
2. `enrichment_agent` enriches scan evidence with vulnerability, ExploitDB, IOC, and knowledge-base context.
3. `correlation_agent` correlates vulnerabilities, alerts, logs, and generated detections.
4. `prediction_agent` predicts likely attacker next steps and defensive watchpoints.
5. `reporting_agent` writes the SOC threat-intelligence report.
6. `response_agent` writes response and remediation actions.
7. The full result is saved to SQLite in `outputs/threat_intel_results.db`.

Backward-compatible aliases still exist for older code paths:

- `nmap_scan_agent` maps to `collection_agent`.
- `vulnerability_scan_agent` maps to `enrichment_agent`.
- `remediation_agent` maps to `response_agent`.

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

Use a custom target with an existing evidence file:

```bash
python crew_threat_intel.py 172.17.0.2 --reuse-scan path/to/evidence.json --ports 1-10000 --timeout 180
```

Threat-intel runs require existing collected evidence. The agents use the LLM plus the ingested
knowledge database, then `tool_generation_agent` creates fresh helper scripts for the run.

```bash
python crew_threat_intel.py 172.17.0.2 --reuse-scan path/to/evidence.json
```

Run the six-stage pipeline against fake test data without live scanning:

```bash
python crew_threat_intel.py 172.17.0.2 \
  --reuse-scan threat_data/test_logs/fake_nmap_scan.json \
  --no-auto-remediation \
  --db-path outputs/test_threat_intel_results.db
```

Fake telemetry logs for tests are included at:

```text
threat_data/test_logs/eve.json
threat_data/test_logs/conn.log
threat_data/test_logs/fake_nmap_scan.json
```

## Red-Team Validation

The red-team pipeline reuses the same enumeration and generated-tool pattern, but focuses on
authorized exploitability validation in a lab.

Specialist agents:

- `red_team_web_attack_agent` for HTTP, Tomcat, AJP, and web middleware checks.
- `red_team_linux_attack_agent` for Linux/Unix network services and legacy daemons.
- `red_team_windows_attack_agent` for SMB, NetBIOS, RDP, WinRM, LDAP, and AD-adjacent checks.
- `red_team_blockchain_attack_agent` for exposed blockchain/node RPC metadata checks.
- `red_team_exploit_planner_agent` coordinates the specialist findings into one plan.
- `red_team_tool_generation_agent` writes reviewable validation scripts.
- `red_team_reporting_agent` summarizes validation evidence.

Specialist task files:

- `tasks/red_team_web_tasks.py`
- `tasks/red_team_linux_tasks.py`
- `tasks/red_team_windows_tasks.py`
- `tasks/red_team_blockchain_tasks.py`

Generate a red-team plan and validation tools without executing them:

```bash
python crew_red_team.py 172.17.0.2 --reuse-scan outputs/runs/run_0022/nmap_scan.json --ports 1-10000
```

Execute the generated validation tools:

```bash
python crew_red_team.py 172.17.0.2 --reuse-scan outputs/runs/run_0022/nmap_scan.json --ports 1-10000 --execute
```

Artifacts are written under:

```text
outputs/runs/run_0001/red_team_plan.json
outputs/runs/run_0001/red_team_report.md
outputs/runs/run_0001/red_team_used.json
outputs/runs/run_0001/red_team_tools/
outputs/generated_red_team_tools/
```

Generated tools are bounded to the supplied target and avoid persistence, credential theft, and
destructive actions.

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

List registered agents:

```bash
curl -s http://127.0.0.1:8000/api/agents | python -m json.tool
```

Run the full red-team pipeline through the API:

```bash
curl -s -X POST http://127.0.0.1:8000/api/red-team/run \
  -H "Content-Type: application/json" \
  -d '{"target":"172.17.0.2","reuse_scan":"outputs/runs/run_0022/nmap_scan.json","execute":false}' \
  | python -m json.tool
```

Run one red-team specialist agent through the API:

```bash
curl -s -X POST http://127.0.0.1:8000/api/red-team/agents/red_team_web_attack_agent/run \
  -H "Content-Type: application/json" \
  -d '{"domain":"web","target":"172.17.0.2","execute":true}' \
  | python -m json.tool
```

Single-specialist runs call fresh enumeration by default and write a compact folder such as:

```text
outputs/runs/run_0001/web_agent/result.json
outputs/runs/run_0001/web_agent/executive_summary.md
outputs/runs/run_0001/web_agent/manifest.json
outputs/runs/run_0001/web_agent/execution/execution_results.json
```

Use `reuse_scan` only when you intentionally want to skip enumeration and replay a previous scan.
Set `use_nmap_agent:false` if you want direct `nmap_tool` execution instead of `nmap_scan_agent`.

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
outputs/runs/run_0001/correlation_report.md
outputs/runs/run_0001/prediction_report.md
outputs/runs/run_0001/soc_report.md
outputs/runs/run_0001/remediation_plan.md
outputs/runs/run_0001/nmap_agent_output.txt
```

Table:

```text
threat_intel_runs
```

The table includes target, ports, raw scan JSON, service summary, threat-intel enrichment, and the final SOC report.
