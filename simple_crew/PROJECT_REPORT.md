# Simple Crew Autonomous Cybersecurity Platform

## Project report from inception to current status

**Repository:** `samar-mhenni/stage`

**Project branch:** `medflow-security-assessment`

**Current branch commit:** `48bcc04`
**Report date:** 28 July 2026

---

## 1. Executive summary

Simple Crew is an autonomous, planner-driven cybersecurity platform with two connected workflows:

1. A **Red Team workflow** that performs authorized API and service security assessments, generates bounded test tools, executes them, interprets HTTP evidence, and produces a report.
2. A **Threat Intelligence workflow** that receives and correlates Wazuh alerts, analyzes supported threats, selects corrective actions, applies a guarded temporary SSH firewall block when justified, generates a report, and emails confirmed findings.

The main MedFlow demonstration proved that trusting a client-controlled `x-user-role` header permits unauthorized reads, privileged function access, prescription modification, and admin-dashboard access. A separate Wazuh demonstration detected five rapid SSH authentication failures from `3.66.188.1`, produced a threat-intelligence report, applied and verified a temporary UFW block on the protected host, scheduled rollback, and sent an email.

The platform is functional, but it is not yet consistently reliable across fully autonomous Red Team reruns. The current general planner may generate incomplete test coverage, generated scripts do not always preserve HTTP error bodies, and Groq's rolling token quotas frequently stop multi-agent runs. These limitations must be stated honestly when presenting the project.

---

## 2. Initial problem and objectives

### 2.1 Original MedFlow assignment

The initial target was a patient-portal API exposed directly through an AWS Lambda Function URL:

`https://rhkcphqmwjyof4zlfzeimytoc40tidgo.lambda-url.eu-central-1.on.aws`

The supplied identity was:

```http
x-user-id: 301
x-user-role: patient
```

The documented endpoints were:

- `GET /patients/{id}`
- `GET /patients`
- `PUT /patients/{id}/prescribe`
- `GET /admin/dashboard`

The required security tests were:

- Recon
- IDOR/BOLA
- Function-level authorization
- Privilege escalation through an unauthorized write
- Admin escalation

The assignment required the language model to interpret every HTTP response, decide PASS or FAIL, identify root causes, classify vulnerabilities, and automatically generate a report with raw evidence.

### 2.2 Expanded project objective

The project later expanded from one API assessment into an end-to-end security platform:

- autonomous Red Team testing;
- generic context-driven operation;
- LLM-generated test scripts;
- safe execution and evidence preservation;
- HTTP credential-audit capability for authorized labs;
- Wazuh real-time alert ingestion;
- failed-login correlation;
- threat analysis and ATT&CK mapping;
- guarded automated remediation;
- report generation;
- email notification.

---

## 3. Development journey

### Phase 1 — MedFlow-specific autonomous assessment

The first working flow generated one authorization-matrix collector. It executed the complete MedFlow test matrix and produced evidence IDs E-001 through E-020.

This run established the successful reference result:

- Recon: PASS
- IDOR/BOLA: FAIL
- Function-level authorization: FAIL
- Unauthorized write: FAIL
- Admin escalation: FAIL

The historical report is stored in:

`simple_crew/outputs/scenario1.md`

### Phase 2 — Simplification and generalization

Scenario-specific routing and hard-coded MedFlow planner decisions were removed. The Red Team workflow now uses a general LLM planner and loads optional context from a JSON file beneath `simple_crew/samples/`.

The tests in the MedFlow context remain names-only:

```json
[
  "Recon",
  "IDOR",
  "Function authorization",
  "Write escalation",
  "Admin escalation"
]
```

The workflow code does not contain MedFlow-specific endpoint logic. The context supplies the authorized target, identity, endpoint templates, account mapping, evidence requirements, and safety rules.

### Phase 3 — Identifier ambiguity fix

An autonomous rerun confused authentication account IDs `301/302/303` with patient-record IDs `1/2/3`, producing requests such as `/patients/302`.

The context was corrected without reintroducing hard-coded workflow behavior:

```text
x-user-id uses account_id; {id} in endpoint paths uses patient_record_id.
```

Accounts now have named fields:

- `account_id`: identity value used in `x-user-id`;
- `patient_record_id`: resource identifier used in `/patients/{id}`.

The subsequent run correctly generated:

```http
GET /patients/2
x-user-id: 301
x-user-role: patient
```

and received:

```http
403
{"message":"Accès refusé à ce dossier"}
```

This confirmed that the context correction worked.

### Phase 4 — Threat Intelligence and Wazuh integration

The platform was extended to accept Wazuh alerts in real time, append every accepted alert to a JSONL ledger, correlate failed logins, and create incident snapshots when the threshold is reached.

Automatic analysis was deliberately separated from ingestion. Wazuh can continuously send alerts, but the operator explicitly starts the full workflow through:

```http
POST /threat-intel/wazuh/run
Authorization: Bearer <WAZUH_INGEST_TOKEN>
```

### Phase 5 — Automated containment and notification

The Corrective Actions agent can select the named action:

`temporary_source_ip_block`

A guarded deterministic executor then validates and applies the action. It connects over SSH to the protected host, creates a UFW deny rule limited to TCP port 22, verifies the rule, and schedules automatic deletion through a transient systemd timer.

The Threat Intelligence workflow sends an email only when an agent result contains an explicitly confirmed finding.

---

## 4. Current architecture

### 4.1 General orchestration loop

Both workflows follow the same compact loop:

1. Search existing ChromaDB collections for relevant security knowledge.
2. Build compact state and database context.
3. Ask the planner for exactly one next action.
4. Route that action to one specialized agent.
5. Save generated tools, execution results, findings, and failures.
6. Repeat until `finish` or the iteration limit.
7. Always attempt to produce a Markdown report.

### 4.2 Red Team agents

- Recon Agent
- Web Analysis Agent
- Exploitation Validation Agent
- Planner Agent
- Tool Generator Agent
- Report Agent

Allowed planner actions:

- `recon`
- `web_analysis`
- `exploit_validation`
- `generate_tool`
- `execute_tool`
- `finish`

### 4.3 Threat Intelligence agents

- Evidence Agent
- Intelligence Agent
- Corrective Actions Agent
- Planner Agent
- Tool Generator Agent
- Report Agent

Required phases are enforced in order:

1. Normalize and process evidence.
2. Analyze and correlate evidence.
3. Produce corrective actions.
4. Generate and execute a bounded defensive helper when required.
5. Produce the final report.
6. Notify by email when a finding is confirmed.

### 4.4 Knowledge retrieval

The project reuses the existing ChromaDB and embedding implementation. Relevant collections include:

- `attack_db`
- `redteam_db`
- `actor_db`
- `detection_db`
- `threat_intel_db`
- `exploit_db`

This provides ATT&CK techniques, exploit knowledge, threat patterns, and detection context without creating a second database.

### 4.5 Model providers

The main assignment model is:

- Provider: Groq
- Model: `openai/gpt-oss-120b`
- Endpoint: `https://api.groq.com/openai/v1`
- Temperature: `0.1`

The application supports three configured Groq key slots and round-robin selection. OpenRouter is available as an alternative provider; a free `openai/gpt-oss-20b` attempt generated and executed tools but stalled during analysis.

No API key is written into reports or committed context files.

---

## 5. Tool-calling and execution design

### 5.1 Generated Red Team tools

The Tool Generator Agent returns a structured object containing:

- tool ID;
- name and purpose;
- language and filename;
- required programs;
- exact argument-list command;
- complete source code;
- expected output;
- risk level.

The tool is saved beneath `simple_crew/generated_tools/`. Generation and execution are separate planner actions. A generated tool is never executed automatically in the same step in which it was created.

### 5.2 Safe executor controls

The executor:

- requires explicit target scope;
- rejects path traversal;
- rejects shell operators and command substitution;
- never uses `shell=True`;
- restricts executable names;
- uses argument lists;
- enforces timeouts and output limits;
- records exit code, duration, stdout, and stderr;
- limits retries;
- prevents repeating a successfully executed tool.

### 5.3 Evidence model

For HTTP tests, the desired evidence record contains:

- timestamp;
- method;
- URL/path;
- request headers;
- request body;
- response status;
- response headers;
- response body.

Raw workflow state is saved as JSON, while the human-readable assessment is saved as Markdown in `simple_crew/outputs/`.

---

## 6. MedFlow assessment results

### 6.1 Root cause

The API trusts the client-supplied `x-user-role` header. The caller can keep the authenticated user ID fixed at `301` and claim to be a doctor or administrator.

The vulnerable authorization decision is conceptually:

```text
client-provided role → endpoint authorization
```

The secure design should be:

```text
verified identity → server-side role lookup or signed claim → object/function authorization
```

### 6.2 Successful reference evidence

The historical complete run recorded:

| Test | Key request | Response | Security verdict |
|---|---|---:|---|
| Recon | `GET /patients/1` as patient | 200 | PASS |
| IDOR baseline | `GET /patients/2` as patient | 403 | PASS for baseline |
| IDOR exploit | `GET /patients/2` as forged doctor | 200 | FAIL |
| IDOR exploit | `GET /patients/3` as forged doctor | 200 | FAIL |
| Patient-list escalation | `GET /patients` as forged doctor | 200 | FAIL |
| Admin escalation | `GET /admin/dashboard` as forged admin | 200 | FAIL |
| Write escalation | `PUT /patients/2/prescribe` as forged doctor | 200 | FAIL |
| Write escalation | `PUT /patients/3/prescribe` as forged admin | 200 | FAIL |
| Cleanup | Restore patient 2 and 3 medications | 200 | Completed |

The dashboard response also disclosed an internal database connection string.

### 6.3 Vulnerability classification

| Finding | Classification |
|---|---|
| Reading another patient's record | OWASP API1:2023 BOLA; CWE-639 |
| Reaching privileged functions through a forged role | OWASP API5:2023 BFLA; CWE-862/CWE-863 |
| Modifying another patient's prescription | OWASP API1:2023 BOLA; CWE-639/CWE-284 |
| Forging an administrative role | CWE-269/CWE-345 |
| Admin response leaking internal configuration | CWE-200 |

### 6.4 Latest regression status

The latest corrected-context run proved that the agent now distinguishes account IDs from patient-record IDs. It successfully tested:

- `/patients/2` as patient → 403;
- `/admin/dashboard` as patient → 403.

The complete elevated-role matrix was not finished because Groq's rolling daily quota interrupted later agent calls. These recent partial runs do not replace the historical complete evidence.

---

## 7. Wazuh and Threat Intelligence workflow

### 7.1 Infrastructure

The demonstrated lab contains:

- Attacker machine: `3.66.188.1`
- Protected AWS host: `63.184.123.234`
- Wazuh manager: separate WSL/Ubuntu environment
- Simple Crew API: this project machine, listening on port 8010

These systems must have network connectivity:

- the protected host sends security events to Wazuh;
- Wazuh forwards JSON alerts to Simple Crew;
- Simple Crew connects to the protected host over SSH when guarded remediation is approved by the agent result;
- Simple Crew connects to Gmail SMTP for confirmed-finding email delivery.

### 7.2 Wazuh ingestion

Endpoint:

```http
POST /threat-intel/ingest/wazuh
Authorization: Bearer <WAZUH_INGEST_TOKEN>
```

Every accepted alert is appended to:

`simple_crew/outputs/wazuh_live_alerts.jsonl`

The ingestion component extracts:

- timestamp;
- source IP;
- username;
- HTTP path or SSH service;
- rule level;
- rule groups;
- authentication outcome.

### 7.3 Correlation logic

Failed authentication events are grouped by:

```text
(source IP, username, path/service)
```

The default trigger is five failed logins within 30 seconds. A Wazuh level-10 brute-force alert can also trigger or enrich an existing incident. A cooldown prevents duplicate incidents.

Incident snapshots are stored as:

`simple_crew/outputs/wazuh_bruteforce_<id>.json`

### 7.4 Manual start behavior

Alert ingestion does not automatically start an LLM workflow. It returns:

```json
{
  "workflow_started": false,
  "start_mode": "manual"
}
```

The operator starts analysis when ready:

```bash
curl -X POST http://127.0.0.1:8010/threat-intel/wazuh/run \
  -H "Authorization: Bearer $WAZUH_INGEST_TOKEN"
```

This preserves human control over when analysis, remediation, and email actions begin.

### 7.5 Demonstrated brute-force incident

The reference incident contained five SSH failures in approximately five seconds:

- Source: `3.66.188.1`
- Username: `wazuh-lab-invalid`
- Target service: SSH/TCP 22
- Wazuh rule: 5710
- ATT&CK mapping: T1110.001 Password Guessing
- Successful login in supplied evidence: none

The evidence supports a high-confidence automated brute-force attempt. It does not prove credential compromise because no successful authentication was observed.

---

## 8. Automated corrective action

### 8.1 Agent decision

The Corrective Actions agent must emit a confirmed finding with:

```text
type = temporary_source_ip_block
target = source public IP
confirmed = true
```

The LLM selects the action and target; it does not directly execute arbitrary shell code.

### 8.2 Guarded execution

Before applying the block, the executor verifies:

- remediation is enabled;
- the address is a valid public IP;
- the address is not private, loopback, multicast, or trusted;
- the protected SSH host value is valid;
- the SSH private key exists and has restrictive permissions;
- block duration is between 60 and 86,400 seconds;
- the source being blocked is not the current administrative SSH source.

### 8.3 Applied command behavior

The executor connects to `63.184.123.234` and performs the equivalent of:

```text
UFW deny from the attacker IP to TCP port 22
```

It then:

- confirms the rule appears in `ufw status`;
- schedules automatic deletion with `systemd-run`;
- records stdout, stderr, status, duration, target, and rollback state.

The verified incident recorded:

- action: `temporary_source_ip_block`;
- target: `3.66.188.1`;
- status: `applied_verified`;
- rollback: `scheduled`.

The supporting workflow state is:

`simple_crew/outputs/ti-c32a60e1a331.json`

---

## 9. Email notification

Email is sent only when:

- the workflow is live, not a dry run;
- at least one finding is explicitly confirmed;
- email alerts are enabled;
- SMTP configuration is complete.

The configured recipient is:

`samar.mhenni.work@gmail.com`

The email includes:

- workflow ID;
- objective;
- evidence path;
- report path;
- confirmed findings;
- report text.

Multiple saved Threat Intelligence states record `notification.status = sent`, including the verified remediation workflow.

Credentials are loaded from environment variables. Gmail uses an App Password, not the normal Google password.

---

## 10. API and operator interfaces

Current endpoints:

- `GET /health`
- `POST /red-team/run`
- `POST /threat-intel/run`
- `POST /threat-intel/ingest/wazuh`
- `POST /threat-intel/wazuh/run`
- `GET /reports/{workflow_id}`

The API is currently healthy:

```json
{"status":"ok"}
```

Red Team live execution requires:

- target;
- explicit authorized scope;
- objective;
- optional context JSON;
- iteration limit;
- `dry_run: false`.

---

## 11. Safety, authorization, and operational boundaries

The project is designed for authorized environments.

Important controls:

- Red Team targets must be explicitly in scope.
- Generated tools cannot freely invoke a shell.
- Active changes require later planner selection and guarded execution.
- Write tests should use synthetic markers and restore original values.
- Firewall containment is narrow, temporary, verified, and reversible.
- Trusted and administrative IPs are protected from accidental blocking.
- Secrets remain in environment variables or external key files.
- Dry-run evidence is labeled simulated and cannot confirm a vulnerability.

---

## 12. Verified artifacts

| Artifact | Purpose |
|---|---|
| `simple_crew/outputs/scenario1.md` | Complete historical MedFlow assessment and E-001–E-020 evidence table |
| `simple_crew/outputs/scenario1 workflow.json` | Historical workflow state and raw evidence |
| `simple_crew/samples/medflow_pre_exploitation_context.json` | Current compact MedFlow context with corrected identifier semantics |
| `simple_crew/outputs/wazuh_live_alerts.jsonl` | Append-only Wazuh live-alert ledger |
| `simple_crew/outputs/wazuh scenario full.md` | Reference brute-force threat-intelligence report |
| `simple_crew/outputs/ti-c32a60e1a331.json` | Verified firewall-remediation and email workflow state |
| `simple_crew/outputs/rt-50390818f554.json` | Corrected patient-record ID request evidence |
| `simple_crew/outputs/rt-fa1e0e99e558.json` | Latest quota-limited retry |

---

## 13. Current limitations

### 13.1 Model quota

Groq enforces:

- approximately 8,000 tokens per minute;
- 200,000 tokens per rolling 24 hours for the observed service tier.

The daily quota does not restore at a constant rate. Tokens return when earlier calls leave the rolling 24-hour window. A tiny key test can succeed while a full 3,000–7,000-token agent call receives HTTP 429.

### 13.2 Planner completeness

The generalized Red Team planner does not always build a complete authorization matrix within eight iterations. It may generate one test per tool and consume too many LLM calls before reaching every required role and endpoint.

### 13.3 Generated-script robustness

Some generated Python scripts:

- treat an expected HTTP 403 as an exception;
- exit with code 1 even after capturing useful evidence;
- omit the HTTP error body;
- use deprecated `datetime.utcnow()`;
- select incomplete role or endpoint combinations.

### 13.4 Report consistency

An LLM-generated narrative has sometimes contradicted the authoritative execution ledger. The ledger is generated directly from state and should be treated as the source of truth.

### 13.5 Evidence confidence

Verdict meanings:

- **PASS:** valid evidence shows the application resisted the unauthorized action.
- **FAIL:** valid evidence shows unauthorized data, functionality, or modification.
- **INCONCLUSIVE:** the correct test was not executed, the evidence is missing, or the script tested the wrong input.

An HTTP 404 for `/patients/302` cannot prove security for the required `/patients/2` test.

---

## 14. Recommended next improvements

### Priority 1 — Deterministic test-case completeness

Add a generic authorization-matrix validator that derives cases from:

- endpoint templates;
- resource identifiers;
- baseline identity;
- candidate role values;
- required test names.

The validator should reject a report as complete until every required case has request and response evidence.

### Priority 2 — Evidence-first HTTP library

Generated tools should reuse one fixed HTTP evidence helper that captures normal responses and `HTTPError` responses identically. Expected 4xx responses should not be interpreted as script crashes.

### Priority 3 — Separate execution success from security result

Use two fields:

```text
execution_status = success
security_verdict = PASS or FAIL
```

A test that correctly receives 403 should have successful execution and a security PASS, not an execution failure.

### Priority 4 — Reduce LLM token consumption

- Generate a complete test-case JSON in one planner action.
- Generate one matrix collector instead of many single-request scripts.
- Analyze compact normalized evidence rather than full repeated workflow state.
- Use deterministic completion routing while keeping vulnerability logic generic.

### Priority 5 — Report validation

Before saving the report:

- compare every reported tool status with the execution ledger;
- verify every PASS/FAIL has evidence;
- prohibit unsupported claims;
- label missing cases INCONCLUSIVE;
- include cleanup verification for every successful write.

### Priority 6 — Operational hardening

- Put the Simple Crew API behind a private tunnel or firewall allowlist.
- Rotate bearer and SMTP credentials.
- Store SSH keys outside the repository.
- Add persistent correlation state if the API restarts.
- Monitor scheduled firewall rollback and record its completion.
- Add tests for Wazuh ingestion, correlation, remediation refusal, and report consistency.

---

## 15. Presentation talking points

### The problem

- Serverless APIs can expose serious authorization flaws even when endpoints return correct responses for normal users.
- Manual testing is slow and can miss role/object combinations.
- Detection without response leaves a gap between identifying an attack and containing it.

### The solution

- An autonomous agent plans tests, generates bounded scripts, executes them, interprets evidence, and reports findings.
- A second workflow converts Wazuh alerts into correlated incidents, threat intelligence, corrective action, verified containment, and email notification.

### What makes the project autonomous

- The planner chooses one next action at a time.
- The model generates tools and interprets responses.
- The workflow persists state and evidence automatically.
- Required Threat Intelligence phases are enforced.
- Corrective action is selected by the agent and executed through a guarded adapter.

### What makes it safe

- Explicit target authorization.
- Bounded executor.
- No arbitrary shell execution.
- Separate generation and execution decisions.
- Temporary reversible firewall changes.
- Trusted-IP and administrative-session protection.
- Evidence-based reporting.

### Strongest Red Team result

- Keeping `x-user-id: 301` fixed while forging `x-user-role` was sufficient to read other patient records, list patients, modify prescriptions, and open the admin dashboard.
- The root cause was client-controlled authorization data.

### Strongest Blue Team result

- Five rapid failed SSH logins were correlated into a brute-force incident.
- The agent selected a temporary source-IP block.
- The executor applied and verified the UFW rule on the protected machine.
- Rollback was scheduled.
- The confirmed report was emailed.

### Honest limitations

- Recent full reruns were interrupted by Groq daily quotas.
- The general Red Team planner still needs deterministic coverage validation.
- Some generated scripts mishandle expected 4xx responses.
- LLM report text must be checked against raw execution state.

### Main lesson

Autonomy should not mean unlimited model freedom. The strongest design combines:

- model reasoning for planning, interpretation, and prioritization;
- deterministic controls for scope, evidence, completeness, execution, and remediation.

---

## 16. Conclusion

The project has progressed from a single autonomous MedFlow assessment into a two-sided security platform covering offensive validation and defensive response. It has demonstrated real authorization vulnerabilities, real Wazuh alert processing, verified temporary containment on a protected host, report generation, and email delivery.

The central architecture is sound: specialized agents reason over compact context, while deterministic components enforce authorization, safe execution, evidence persistence, required workflow phases, and reversible remediation.

The project is currently best described as a **functional security automation prototype with successful end-to-end demonstrations and known reliability limitations**. The next engineering milestone is to make Red Team coverage deterministic and evidence handling uniform so that a generalized autonomous rerun reliably reproduces the complete test matrix without scenario-specific workflow code.
