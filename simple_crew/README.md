# Simple Crew

`simple_crew` is a small planner-driven alternative to the existing project. It does not replace or import the legacy orchestration layer.

## Architecture

Each workflow is one short loop:

1. Search the existing ChromaDB collections.
2. Build compact context from recent results and relevant database records.
3. Ask the planner for exactly one next action.
4. Route that action directly to one worker agent.
5. Store the result and repeat within the iteration limit.
6. Always produce a report.

Each agent has one file under `agents/red_team/` or `agents/threat_intel/` containing its role, goal, and safety-aware backstory. Each matching task has one file under `tasks/red_team/` or `tasks/threat_intel/` containing its focused instructions and strict output contract. The workflow keeps only a small direct name-to-function map for routing; there are no registry classes or generic factory frameworks. One generic task runner handles the CrewAI call and Pydantic parsing.

### Red Team agents

- Recon Agent
- Web Agent
- Web Authorization Testing Agent
- Exploitation Agent
- Planner Agent
- Tool Generator Agent
- Report Agent

The workflow is limited to explicitly authorized targets. The exploitation agent performs only controlled, least-invasive validation selected by the planner.

When a supplied JSON context contains HTTP endpoints, identity data, and named authorization tests,
the workflow routes through the Web Authorization Testing Agent. It produces one complete structured
test matrix. A deterministic validator rejects missing tests, endpoints, roles, resource identifiers,
or fixed identity headers. Only a validated matrix is converted into one bounded HTTP collector.
The collector preserves HTTP 4xx responses as evidence instead of treating them as transport failures.

### Threat Intelligence agents

- Evidence Agent
- Intelligence Agent
- Corrective Actions Agent
- Planner Agent
- Tool Generator Agent
- Report Agent

Simple JSON, JSONL, CSV, indicator extraction, deduplication, and truncation happen locally before LLM analysis.

## Existing configuration reused

The shared LLM function in `config.py` uses the existing environment variables:

- `LLM_PROVIDER`
- `GROQ_API_KEY`, optional `GROQ_API_KEY_SECONDARY` and `GROQ_API_KEY_TERTIARY`, `GROQ_BASE_URL`, `GROQ_MODEL`
- `OPENROUTER_API_KEY`, `OPENROUTER_BASE_URL`, `QWEN_MODEL`

It preserves the existing low temperature of `0.1`. No key is stored in this directory.

The database adapter reuses the existing persistent ChromaDB at `./chroma_db`, configured by `CHROMADB_PATH`, and the existing `BAAI/bge-base-en-v1.5` retrieval implementation. Relevant collections are:

- `attack_db`
- `redteam_db`
- `actor_db`
- `detection_db`
- `threat_intel_db`
- `exploit_db`

No new vector database or ingestion pipeline is created.

## Setup

From the repository root:

```bash
python -m venv venv
venv/bin/pip install -r requirements.txt
```

The existing root `.env` is loaded automatically. `simple_crew/.env.example` documents the reused variable names without secrets.

## CLI

Red Team dry run:

```bash
venv/bin/python -m simple_crew.main red-team \
  --target 127.0.0.1 \
  --target-port 18080 \
  --scope 127.0.0.1 \
  --objective "Authorized dry-run assessment of the local lab" \
  --max-iterations 12 \
  --dry-run
```

Threat Intelligence dry run:

```bash
venv/bin/python -m simple_crew.main threat-intel \
  --evidence simple_crew/samples/synthetic_alerts.json \
  --objective "Analyze the synthetic alerts and recommend corrective actions" \
  --max-iterations 12 \
  --dry-run
```

Use `--live` to enable the configured LLM. Red Team live execution still requires an explicit scope, and a generated tool runs only if the planner later selects `execute_tool`.

Start the API:

```bash
venv/bin/python -m simple_crew.main api --host 127.0.0.1 --port 8010
```

## API

Endpoints:

- `GET /health`
- `POST /red-team/run`
- `POST /threat-intel/run`
- `GET /reports/{workflow_id}`

Compatibility aliases are also available at `/api/red-team/run` and `/api/threat-intel/run`.

Red Team example:

```bash
curl -sS -X POST http://127.0.0.1:8010/red-team/run \
  -H 'Content-Type: application/json' \
  -d '{
    "target":"127.0.0.1",
    "target_port":18080,
    "authorized_scope":["127.0.0.1"],
    "objective":"Authorized assessment of the local lab",
    "max_iterations":12,
    "dry_run":true
  }'
```

Threat Intelligence example:

```bash
curl -sS -X POST http://127.0.0.1:8010/threat-intel/run \
  -H 'Content-Type: application/json' \
  -d '{
    "evidence_path":"simple_crew/samples/synthetic_alerts.json",
    "objective":"Analyze suspicious activity and recommend corrective actions",
    "max_iterations":12,
    "dry_run":true
  }'
```

## Generated tools and safety

Generated tools are saved only under `simple_crew/generated_tools/`. The executor:

- rejects Red Team targets outside explicit scope;
- never uses `shell=True`;
- rejects shell operators and command substitution;
- restricts executable names;
- prevents generated-file path traversal;
- uses argument lists, timeouts, output limits, and a fixed working directory;
- records status, exit code, duration, stdout, and stderr;
- never runs a tool immediately after generation—the planner must select `execute_tool` in a later iteration.

Dry-run mode routes through generation and execution decisions but returns a skipped execution result and runs no security command.

## Verification

```bash
venv/bin/python -m compileall -q simple_crew

venv/bin/python - <<'PY'
from simple_crew.api.app import app
from simple_crew.workflows import run_red_team, run_threat_intel
print(app.title, run_red_team.__name__, run_threat_intel.__name__)
PY

venv/bin/uvicorn simple_crew.api.app:app --host 127.0.0.1 --port 8010
curl -sS http://127.0.0.1:8010/health
```

Reports and compact workflow-result records are written beneath `simple_crew/outputs/`.

## Real-time Wazuh ingestion

Wazuh can push JSON alerts to `POST /threat-intel/ingest/wazuh`. The endpoint requires
`Authorization: Bearer <WAZUH_INGEST_TOKEN>`, appends every accepted alert to
`simple_crew/outputs/wazuh_live_alerts.jsonl`, and deterministically correlates failed logins by
source IP, username, and path. When the configured threshold is reached, it saves an incident
snapshot but does not start analysis or remediation automatically. Start the complete workflow
manually with `POST /threat-intel/wazuh/run`; it selects the newest correlated Wazuh incident,
completes evidence processing, analysis, named corrective actions and guarded remediation, writes
a report, and emails the report.

```bash
export WAZUH_INGEST_TOKEN='generate-a-long-random-token'
export WAZUH_BRUTEFORCE_THRESHOLD=5
export WAZUH_BRUTEFORCE_WINDOW_SECONDS=30
export WAZUH_ALERT_COOLDOWN_SECONDS=300
export WAZUH_LEVEL10_GRACE_SECONDS=2
venv/bin/uvicorn simple_crew.api.app:app --host 0.0.0.0 --port 8010
```

Keep port 8010 private and allow only the Wazuh machine. A successful ingestion response reports
the current correlation count, incident snapshot path, and `start_mode: manual`. Start the newest
ready incident explicitly:

```bash
curl -X POST http://127.0.0.1:8010/threat-intel/wazuh/run \
  -H "Authorization: Bearer $WAZUH_INGEST_TOKEN"
```

For the authorized SSH lab, the Corrective Actions agent may select the machine-readable action
`temporary_source_ip_block`. A fixed executor validates the public source IP, trusted-IP exclusions,
SSH key permissions, protected host, and duration before applying a TCP/22 UFW deny rule. It verifies
the rule and schedules automatic removal. The LLM never generates firewall source code. Configure
the `REMEDIATION_*` settings for the protected host and keep its private key outside the project.

## Threat Intel email alerts

After a live Threat Intel run writes its report, it sends an email only when an agent finding is
explicitly marked `confirmed: true`. Delivery status is stored in the workflow state's
`notifications` array. Configure SMTP without committing credentials:

```bash
export EMAIL_ALERTS_ENABLED=true
export ALERT_EMAIL_TO=samar.mhenni.work@gmail.com
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USERNAME=your-sender@gmail.com
export SMTP_PASSWORD=your-google-app-password
export SMTP_STARTTLS=true
```

For Gmail, use an App Password rather than the normal account password. Dry runs and workflows
without an explicitly confirmed finding record a skipped notification and send nothing.

## Bounded HTTP credential audits

An explicitly authorized login audit can be described with
`simple_crew/samples/http_credential_audit_context.example.json` and supplied through the Red Team
API's `context_path` field. The workflow requires a target-relative POST path, one or more authorized
test usernames and either an inline password list or a `password_file` containing one candidate per
line. Dictionary files must be stored under `simple_crew/samples`. The workflow also requires a
positive attempt cap, a nonnegative optional delay, and explicit success/failure indicators. It
executes the supplied credential matrix and stops on the first accepted credential or HTTP 423/429.
The credential-audit agent is not activated when the context omits `credential_audit.enabled`.

## Limitations

- Dry-run results are intentionally simulated; they are not evidence of a vulnerability.
- Live workflows require working provider credentials and may be affected by provider quotas.
- The ChromaDB embedding model has a noticeable first-load cost and may contact Hugging Face when not cached.
- The database is reused for retrieval. Workflow outputs are kept as local report/JSONL artifacts rather than added to legacy Chroma collections.
- The safe executor supports a deliberately small program allowlist and is not a general shell runner.
