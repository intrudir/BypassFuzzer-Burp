#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


jar = pathlib.Path(sys.argv[1]).resolve()
evidence = pathlib.Path(sys.argv[2]).resolve()
feature = sys.argv[3]
observed = []


class Lab(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        headers = {name.lower(): value for name, value in self.headers.items()}
        observed.append({"method": "GET", "target": self.path, "headers": list(self.headers.items())})
        decoded = urllib.parse.unquote(self.path)
        status, marker = 403, "blocked-baseline"
        trusted_proxy = headers.get("cf-connecting-ip") in {"127.0.0.1", "localhost", "::1"}
        if self.path.startswith("/private") and trusted_proxy:
            status, marker = 200, "trusted-proxy-ip"
        elif self.path.startswith("/objects/alice"):
            status, marker = 200, "authorized-control"
        elif self.path.startswith("/objects/bob"):
            status, marker = 403, "target-denied"
        elif self.path.startswith("/redirect") and "trusted.example" in decoded and "127.0.0.1" in decoded:
            status, marker = 200, "url-parser-bypass"
        body = marker.encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Verify-Result", marker)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


def raw_request(path, port):
    return f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer verification-secret\r\n\r\n"


def run():
    evidence.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    origin = f"http://127.0.0.1:{port}"
    scan = evidence / "scan"
    with tempfile.TemporaryDirectory(prefix="bypassfuzzer-cli-verify-") as temporary:
        temporary = pathlib.Path(temporary)
        common = ["--output", str(scan), "--protocol", "http1", "--retry-attempts", "0",
                  "--global-concurrency", "3", "--per-host-concurrency", "2", "--redact"]
        common += ["--header", "Authorization: Bearer verification-secret"]
        if feature == "sweep":
            source = temporary / "urls.txt"
            source.write_text(origin + "/private\n", encoding="utf-8")
            args = ["sweep", "--urls", str(source), "--payload-set", "high-signal", "--max-probes", "8"] + common
        elif feature == "bypass":
            source = temporary / "request.raw"
            source.write_bytes(raw_request("/private", port).encode("iso-8859-1"))
            args = ["bypass", "--request", str(source), "--target-origin", origin,
                    "--families", "header", "--max-probes", "300"] + common
        elif feature == "idor":
            source = temporary / "request.raw"
            source.write_bytes(raw_request("/objects/alice?id=alice", port).encode("iso-8859-1"))
            args = ["idor", "--request", str(source), "--target-origin", origin,
                    "--authorized-id", "alice", "--target-id", "bob", "--max-probes", "10"] + common
        else:
            source = temporary / "request.raw"
            source.write_bytes(raw_request("/redirect?next={INJECT}", port).encode("iso-8859-1"))
            args = ["url-validation", "--request", str(source), "--target-origin", origin,
                    "--allowed-host", "trusted.example", "--attacker-host", "127.0.0.1",
                    "--contexts", "absolute-url", "--attacks", "domain-allow-list-bypass",
                    "--encodings", "raw", "--max-probes", "12"] + common
        command = ["java", "-jar", str(jar)] + args
        (evidence / "command.json").write_text(json.dumps(command, indent=2) + "\n", encoding="utf-8")
        result = subprocess.run(command, text=True, capture_output=True, timeout=120)
        (evidence / "stdout.jsonl").write_text(result.stdout, encoding="utf-8")
        (evidence / "stderr.log").write_text(result.stderr, encoding="utf-8")
        if result.returncode != 0:
            raise AssertionError(f"CLI exited {result.returncode}: {result.stderr}")

        bad = temporary / "collaborator.yaml"
        bad.write_text("schemaVersion: 1\nbypass:\n  collaboratorEnabled: true\n", encoding="utf-8")
        boundary = subprocess.run(["java", "-jar", str(jar), "bypass", "--config", str(bad)],
                                  text=True, capture_output=True, timeout=30)
        boundary_text = f"exit={boundary.returncode}\n{boundary.stdout}{boundary.stderr}"
        (evidence / "collaborator-boundary.log").write_text(boundary_text, encoding="utf-8")
        if boundary.returncode != 2 or "Collaborator is not supported" not in boundary_text:
            raise AssertionError("Collaborator configuration was not rejected at preflight")
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)

    summary = json.loads((scan / "summary.json").read_text(encoding="utf-8"))
    lines = [json.loads(line) for line in (scan / "results.jsonl").read_text(encoding="utf-8").splitlines() if line]
    assert summary["state"] == "completed"
    assert summary["mode"] == feature
    assert summary["transportErrors"] == 0
    assert summary["records"] == len(lines) and len(lines) > 1
    assert lines[0]["baseline"] is True
    for item in lines:
        assert (scan / item["requestRef"]).is_file()
        if item["responseRef"]:
            assert (scan / item["responseRef"]).is_file()
    stored = "\n".join(path.read_text(encoding="iso-8859-1") for path in (scan / "requests").glob("*.raw"))
    assert "verification-secret" not in stored
    assert "Authorization: [REDACTED]" in stored
    if feature == "bypass":
        assert summary["findings"] > 0
        assert "CF-Connecting-IP: 127.0.0.1" in stored
        assert any(item["signal"] == "LIKELY_BYPASS" and item["status"] == 200 for item in lines)
    elif feature == "idor":
        assert [item["payload"] for item in lines[:2]] == ["idor.baseline.control", "idor.baseline.target"]
        assert any(not item["baseline"] for item in lines[2:])
    elif feature == "url-validation":
        mutation_refs = [scan / item["requestRef"] for item in lines if not item["baseline"]]
        assert mutation_refs and all("{INJECT}" not in path.read_text(encoding="iso-8859-1") for path in mutation_refs)
    (evidence / "lab-requests.json").write_text(json.dumps(observed, indent=2) + "\n", encoding="utf-8")
    assertions = {"state": "PASS", "mode": feature, "records": len(lines),
                  "findings": summary["findings"], "labRequests": len(observed),
                  "collaboratorRejected": True, "redactionVerified": True}
    (evidence / "assertions.json").write_text(json.dumps(assertions, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    try:
        run()
    except Exception as error:
        print(f"verification failed: {error}", file=sys.stderr)
        raise
