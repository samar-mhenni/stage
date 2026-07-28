import json

from crews.threat_intel.fallbacks import local_tool_manifest_fallback
from crews.threat_intel.tool_generation_stage import (
    _add_evidence_network_access,
    _remediation_manifest_quality_issues,
)


def test_fallback_builds_endpoint_from_structured_environment():
    evidence = {
        "target": "training-app.internal",
        "environment": {
            "host_ip": "10.20.0.15",
            "port": 8080,
            "service": "Apache Tomcat",
        },
        "events": [],
    }

    manifest = local_tool_manifest_fallback(
        "training-app.internal",
        json.dumps(evidence),
    )

    body = manifest["scripts"][0]["body"]
    assert '"http://10.20.0.15:8080/"' in body
    assert "curl -ksS --max-time 10" in body


def test_evidence_network_access_exports_explicit_url():
    access = {"TARGET": "training-app.internal", "ACCESS_MODE": "network_only"}
    evidence = {"environment": {"host_ip": "10.20.0.15", "port": 8080}}

    _add_evidence_network_access(access, json.dumps(evidence))

    assert access["TARGET_HOST"] == "10.20.0.15"
    assert access["TARGET_PORT"] == "8080"
    assert access["TARGET_URL"] == "http://10.20.0.15:8080/"


def test_network_validator_rejects_unhandled_curl_under_set_e():
    manifest = {
        "scripts": [
            {
                "filename": "unsafe.sh",
                "interpreter": "bash",
                "body": "#!/usr/bin/env bash\nset -euo pipefail\nSTATUS=$(curl -sS \"$TARGET_URL\")\n",
            }
        ]
    }

    issues = _remediation_manifest_quality_issues(manifest, {"ACCESS_MODE": "network_only"})

    assert any("curl failure must be handled" in issue for issue in issues)
