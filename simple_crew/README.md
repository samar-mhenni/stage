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
- Exploitation Agent
- Planner Agent
- Tool Generator Agent
- Report Agent

The workflow is limited to explicitly authorized targets. The exploitation agent performs only controlled, least-invasive validation selected by the planner.

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

## Limitations

- Dry-run results are intentionally simulated; they are not evidence of a vulnerability.
- Live workflows require working provider credentials and may be affected by provider quotas.
- The ChromaDB embedding model has a noticeable first-load cost and may contact Hugging Face when not cached.
- The database is reused for retrieval. Workflow outputs are kept as local report/JSONL artifacts rather than added to legacy Chroma collections.
- The safe executor supports a deliberately small program allowlist and is not a general shell runner.
