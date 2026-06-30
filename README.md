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
outputs/runs/run_0001/soc_report.md
outputs/runs/run_0001/remediation_plan.md
outputs/runs/run_0001/nmap_agent_output.txt
```

Table:

```text
threat_intel_runs
```

The table includes target, ports, raw scan JSON, service summary, threat-intel enrichment, and the final SOC report.
