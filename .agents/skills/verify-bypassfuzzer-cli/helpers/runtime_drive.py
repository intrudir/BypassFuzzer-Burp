#!/usr/bin/env python3
"""Drive packaged runtime controls and results; all traffic stays on owned loopback."""
import json
import pathlib
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

jar = pathlib.Path(sys.argv[1]).resolve()
evidence = pathlib.Path(sys.argv[2]).resolve()
evidence.mkdir(parents=True, exist_ok=True)
commands = []
observed = []


def invoke(name, arguments):
    command = ['java', '-jar', str(jar), *arguments]
    commands.append(command)
    result = subprocess.run(command, capture_output=True, text=True, timeout=45)
    (evidence / (name + '.stdout')).write_text(result.stdout)
    (evidence / (name + '.stderr')).write_text(result.stderr)
    assert result.returncode == 0, (name, result.returncode, result.stderr)
    return result.stdout


def run():
    # The existing owned live driver proves credentials, streaming and raw evidence.
    base = evidence / 'baseline'
    result = subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('live_drive.py')),
                             str(jar), str(base), 'bypass'], capture_output=True, text=True, timeout=180)
    (evidence / 'baseline-driver.log').write_text(result.stdout + result.stderr)
    assert result.returncode == 0
    scan = base / 'scan'
    export = invoke('results-jsonl', ['results', '--input', str(scan), '--show-status', '200', '--format', 'jsonl'])
    rows = [json.loads(line) for line in export.splitlines() if line]
    assert rows and all(row['status'] == 200 for row in rows)
    assert 'Target\tFamily\tPayload' in invoke('results-tsv', ['results', '--input', str(scan)])
    assert invoke('results-hosts', ['results', '--input', str(scan), '--format', 'hosts']).strip()
    assert invoke('results-payloads', ['results', '--input', str(scan), '--format', 'payloads']).strip()
    regex = invoke('results-regex', ['results', '--input', str(scan), '--response-contains',
                                    'trusted.proxy.ip', '--response-regex', '--format', 'jsonl'])
    assert regex.strip()

    admitted = threading.Event()

    class Lab(BaseHTTPRequestHandler):
        def do_GET(self):
            observed.append(self.path)
            admitted.set()
            time.sleep(0.3)
            body = b'owned-loopback-runtime'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Lab)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    process = None
    try:
        origin = 'http://127.0.0.1:' + str(server.server_port)
        request = evidence / 'input.raw'
        request.write_bytes(('GET /private HTTP/1.1\r\nHost: 127.0.0.1:' + str(server.server_port) + '\r\n\r\n').encode())
        job = evidence / 'job.yaml'
        job.write_text('schemaVersion: 1\ninput:\n  request: input.raw\n  targetOrigin: ' + origin
                       + '\nexecution:\n  maxProbes: 1\n  headers: ["X-Audit: yaml"]\nbypass:\n  families: [path]\n')
        preview = invoke('yaml-override', ['bypass', '--config', str(job), '--preview', '--families', 'header',
                                           '--header', 'X-Audit: flag'])
        assert 'X-Audit: flag' in preview and 'X-Audit: yaml' not in preview
        assert not observed, 'Preview sent traffic'
        control = evidence / 'control.txt'
        control.write_text('pause')
        output = evidence / 'controlled-scan'
        command = ['java', '-jar', str(jar), 'bypass', '--request', str(request), '--target-origin', origin,
                   '--families', 'case', '--max-probes', '10', '--protocol', 'http1', '--retry-attempts', '0',
                   '--traffic-max-in-flight', '1', '--traffic-max-rps', '5', '--control-file', str(control),
                   '--output', str(output)]
        commands.append(command)
        with (evidence / 'control.stdout').open('w') as stdout, (evidence / 'control.stderr').open('w') as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            time.sleep(1.5)
            assert process.poll() is None and not observed, 'Initial pause failed'
            control.write_text('resume')
            assert admitted.wait(15), 'Resume did not admit a request'
            control.write_text('stop')
            assert process.wait(timeout=30) == 0
        summary = json.loads((output / 'summary.json').read_text())
        assert summary['state'] == 'stopped' and observed
        (evidence / 'assertions.json').write_text(json.dumps({
            'state': 'PASS', 'resultsFiltersAndExports': True, 'yamlFlagsOverride': True,
            'previewNoTraffic': True, 'pauseResumeStop': True, 'loopbackRequests': len(observed)
        }, indent=2) + '\n')
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        (evidence / 'lab-requests.json').write_text(json.dumps(observed, indent=2) + '\n')


try:
    run()
finally:
    (evidence / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
