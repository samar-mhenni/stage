import base64
import json
import re
from typing import Any
from uuid import uuid4

from simple_crew.models import AuthorizationTestMatrix, GeneratedTool


def is_authorization_context(context: dict[str, Any] | None) -> bool:
    if not isinstance(context, dict):
        return False
    return all(
        isinstance(context.get(key), expected)
        for key, expected in (("endpoints", list), ("tests", list), ("identity", dict))
    ) and bool(context["endpoints"] and context["tests"])


def _endpoint_specs(context: dict[str, Any]) -> list[tuple[str, str, re.Pattern[str]]]:
    specs = []
    for item in context.get("endpoints", []):
        parts = str(item).strip().split(maxsplit=1)
        if len(parts) != 2:
            continue
        method, template = parts[0].upper(), parts[1]
        pattern = re.escape(template)
        pattern = re.sub(r"\\\{[^{}]+\\\}", r"[^/]+", pattern)
        specs.append((method, template, re.compile(f"^{pattern}$")))
    return specs


def _collect_named_values(value: Any, suffixes: tuple[str, ...]) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower().endswith(suffixes) and child is not None:
                found.add(str(child))
            found.update(_collect_named_values(child, suffixes))
    elif isinstance(value, list):
        for child in value:
            found.update(_collect_named_values(child, suffixes))
    return found


def validate_authorization_matrix(
    matrix: AuthorizationTestMatrix,
    context: dict[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    cases = matrix.cases
    if not cases:
        errors.append("matrix contains no cases")
    evidence_ids = [case.evidence_id for case in cases]
    if len(evidence_ids) != len(set(evidence_ids)):
        errors.append("evidence IDs are not unique")

    required_tests = {str(item).strip().casefold() for item in context.get("tests", [])}
    covered_tests = {case.test.strip().casefold() for case in cases}
    for name in sorted(required_tests - covered_tests):
        errors.append(f"missing required test: {name}")

    specs = _endpoint_specs(context)
    covered_specs: set[tuple[str, str]] = set()
    for case in cases:
        matches = [
            (method, template)
            for method, template, pattern in specs
            if case.request.method == method and pattern.fullmatch(case.request.path)
        ]
        if not matches:
            errors.append(
                f"{case.evidence_id} uses undocumented request "
                f"{case.request.method} {case.request.path}"
            )
        covered_specs.update(matches)
        if case.request.method in {"POST", "PUT", "PATCH"} and case.request.body is None:
            errors.append(f"{case.evidence_id} write request has no JSON body")
    for method, template, _ in specs:
        if (method, template) not in covered_specs:
            errors.append(f"endpoint not covered: {method} {template}")

    identity_headers = context.get("identity", {}).get("headers", {})
    for header, expected in identity_headers.items():
        if "role" in header.casefold():
            continue
        for case in cases:
            actual = next(
                (value for key, value in case.request.headers.items() if key.casefold() == header.casefold()),
                None,
            )
            if actual != str(expected):
                errors.append(f"{case.evidence_id} does not keep {header} fixed")

    roles = _collect_named_values(context, ("role",))
    observed_roles = {
        str(value)
        for case in cases
        for key, value in case.request.headers.items()
        if "role" in key.casefold()
    }
    for role in sorted(roles - observed_roles):
        errors.append(f"role value not covered: {role}")

    resource_ids = _collect_named_values(
        context, ("patient_record_id", "resource_id", "record_id", "object_id")
    )
    parameter_paths = [case.request.path for case in cases if re.search(r"/[^/]+", case.request.path)]
    for resource_id in sorted(resource_ids):
        if not any(resource_id in path.strip("/").split("/") for path in parameter_paths):
            errors.append(f"resource identifier not covered: {resource_id}")

    baseline_role = next(
        (
            str(value) for key, value in identity_headers.items()
            if "role" in key.casefold()
        ),
        None,
    )
    identity_id = next(
        (
            str(value) for key, value in identity_headers.items()
            if "id" in key.casefold() and "role" not in key.casefold()
        ),
        None,
    )
    own_resource_id = None
    accounts = context.get("accounts", [])
    if isinstance(accounts, list) and identity_id is not None:
        for account in accounts:
            if not isinstance(account, dict) or str(account.get("account_id")) != identity_id:
                continue
            own_values = _collect_named_values(
                account, ("patient_record_id", "resource_id", "record_id", "object_id")
            )
            own_resource_id = next(iter(own_values), None)
            break

    matched_cases: dict[tuple[str, str], list[Any]] = {}
    for method, template, pattern in specs:
        matched_cases[(method, template)] = [
            case for case in cases
            if case.request.method == method and pattern.fullmatch(case.request.path)
        ]
    for (method, template), endpoint_cases in matched_cases.items():
        has_parameter = "{" in template and "}" in template
        for role in sorted(roles):
            role_cases = [
                case for case in endpoint_cases
                if any(
                    "role" in key.casefold() and str(value) == role
                    for key, value in case.request.headers.items()
                )
            ]
            if not role_cases:
                errors.append(f"endpoint role combination missing: {method} {template} as {role}")
                continue
            if method in {"GET", "HEAD", "OPTIONS"} and has_parameter:
                for resource_id in sorted(resource_ids):
                    if not any(
                        resource_id in case.request.path.strip("/").split("/")
                        for case in role_cases
                    ):
                        errors.append(
                            f"read combination missing: {method} {template} "
                            f"as {role} for resource {resource_id}"
                        )
            elif method in {"POST", "PUT", "PATCH", "DELETE"} and has_parameter:
                required_ids = (
                    {own_resource_id}
                    if role == baseline_role and own_resource_id
                    else resource_ids - ({own_resource_id} if own_resource_id else set())
                )
                for resource_id in sorted(required_ids):
                    matching = [
                        case for case in role_cases
                        if resource_id in case.request.path.strip("/").split("/")
                    ]
                    if not matching:
                        errors.append(
                            f"write combination missing: {method} {template} "
                            f"as {role} for resource {resource_id}"
                        )
                    elif role != baseline_role and any(case.cleanup is None for case in matching):
                        errors.append(
                            f"write cleanup missing: {method} {template} "
                            f"as {role} for resource {resource_id}"
                        )

    return {
        "valid": not errors,
        "errors": errors,
        "case_count": len(cases),
        "covered_tests": sorted(covered_tests),
        "covered_endpoints": sorted(f"{method} {template}" for method, template in covered_specs),
        "covered_roles": sorted(observed_roles),
        "covered_resource_ids": sorted(resource_ids),
    }


def build_authorization_collector(
    matrix: AuthorizationTestMatrix,
    base_url: str,
) -> GeneratedTool:
    tool_id = f"authorization-matrix-{uuid4().hex[:12]}"
    filename = f"{tool_id}.py"
    encoded = base64.b64encode(matrix.model_dump_json().encode()).decode()
    code = f"""import base64,json,sys,urllib.error,urllib.request
M=json.loads(base64.b64decode({encoded!r}))
def send(base,item):
 r=item["request"]; body=r.get("body")
 data=None if body is None else json.dumps(body).encode()
 h={{str(k):str(v) for k,v in r.get("headers",{{}}).items()}}
 if data is not None: h.setdefault("Content-Type","application/json")
 req=urllib.request.Request(base.rstrip("/")+r["path"],data=data,headers=h,method=r["method"])
 try:
  with urllib.request.urlopen(req,timeout=15) as x:
   status=x.status; rh=dict(x.headers); rb=x.read().decode("utf-8","replace")
 except urllib.error.HTTPError as x:
  status=x.code; rh=dict(x.headers); rb=x.read().decode("utf-8","replace")
 return {{"evidence_id":item["evidence_id"],"test":item["test"],"method":r["method"],
 "path":r["path"],"request_headers":h,"request_body":body,"status":status,
 "response_headers":rh,"response_body":rb,"expected_security_behavior":item["expected_security_behavior"]}}
def main():
 if len(sys.argv)!=2: raise SystemExit("target required")
 base=sys.argv[1] if "://" in sys.argv[1] else "https://"+sys.argv[1]
 out=[]; transport_failed=False
 for item in M["cases"]:
  try:
   result=send(base,item); out.append(result)
   cleanup=item.get("cleanup")
   if cleanup and 200<=result["status"]<300:
    cleanup_item={{"evidence_id":item["evidence_id"]+"-C","test":item["test"]+" cleanup",
     "request":cleanup,"expected_security_behavior":"restore state"}}
    out.append(send(base,cleanup_item))
  except Exception as exc:
   transport_failed=True; out.append({{"evidence_id":item["evidence_id"],"test":item["test"],
    "method":item["request"]["method"],"path":item["request"]["path"],"transport_error":str(exc)}})
 print(json.dumps(out,ensure_ascii=False))
 raise SystemExit(1 if transport_failed else 0)
if __name__=="__main__": main()
"""
    return GeneratedTool(
        tool_id=tool_id,
        name="Web Authorization Matrix Collector",
        purpose="Execute the validated authorization test matrix and preserve all HTTP responses.",
        language="python",
        filename=filename,
        required_programs=["python3"],
        command=["python3", filename, base_url],
        code=code,
        expected_output="One JSON array containing request and response evidence for every test case.",
        risk_level="medium",
    )
