from typing import Any

from simple_crew.tasks.common import compact


MATRIX_SCHEMA = """{
  "cases": [{
    "evidence_id": "E-001",
    "test": "one exact supplied test name",
    "request": {
      "method": "GET",
      "path": "/target-relative-path",
      "headers": {"header": "value"},
      "body": null
    },
    "expected_security_behavior": "short expected authorization property",
    "cleanup": null
  }]
}"""


def build_task(context: dict[str, Any]) -> str:
    return f"""Build one complete Web authorization test matrix from the supplied context.
Rules:
- Use only the supplied target-relative endpoint templates, test names, identities, roles,
  resource identifiers, payload information, and safety constraints.
- Treat authentication/account identifiers and URL resource identifiers as different namespaces.
  Follow their field names and any identifier rule exactly.
- Keep the baseline authenticated identity fixed. Vary only values explicitly presented as test
  inputs, such as role values.
- Include every supplied test name and every documented endpoint at least once when applicable.
- For read-only endpoint templates with a resource placeholder, cover every supplied role value
  against every supplied URL resource identifier.
- For static authorization endpoints, cover every supplied role value.
- For write endpoint templates, include the baseline identity case and every supplied elevated role
  against every non-owned resource identifier when those values are available.
- For authorization tests, include both baseline and adversarial variations needed to compare the
  boundary. Do not assume a denial or success response.
- A write request must have a JSON body. Include an explicit cleanup request whenever the context
  provides enough information for safe restoration. If safe write or cleanup data is unavailable,
  keep the case non-destructive and state that limitation in expected_security_behavior.
- Record one request per case. Use unique sequential evidence IDs.
- HTTP 4xx responses are valid evidence and must not be treated as transport failures.
- Do not execute requests, invent responses, add undocumented paths, or leave scope.
Return only JSON matching:
{MATRIX_SCHEMA}
Context: {compact(context, 10000)}"""
