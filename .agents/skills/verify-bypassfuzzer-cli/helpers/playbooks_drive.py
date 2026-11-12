#!/usr/bin/env python3
"""Drive the packaged CLI against owned HTTP fixtures, including a stripping proxy."""
import argparse, contextlib, hashlib, http.client, json, pathlib, subprocess, tempfile, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IDS = ['bypass.header.forwarded', 'bypass.header.hop_by_hop_auth', 'bypass.header.trusted_referer',
       'bypass.path.api_prefix', 'bypass.path.api_version_swap', 'bypass.verb.method_case']
OBSERVED = []

class Origin(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def handle_probe(self):
        path = urllib.parse.urlsplit(self.path).path
        h = self.headers
        row = dict(hop='origin', method=self.command, path=self.path, forwarded=h.get('Forwarded'),
                   referer=h.get('Referer'), nomination=h.get('Connection'), hasAuthorization='Authorization' in h,
                   hasCookie='Cookie' in h, keep=h.get('X-Keep'))
        OBSERVED.append(row)
        status, body = 403, b'denied'
        control = '__bf_control_' in path
        if '/forwarded/' in path and h.get('Forwarded') in ('for="[::1]"', 'For=127.1.1.1'):
            status, body = 200, b'forwarded-confirmed'
        if '/referer/' in path and h.get('Referer', '').endswith(('/admin', '/dashboard', '/internal')):
            status, body = 200, b'referer-confirmed'
        if '/prefix/' in path and path.startswith(('/v2/', '/v3/', '/api/', '/private-api/')):
            status, body = 200, b'prefix-confirmed'
        if '/version/' in path and path.endswith(('/v2/admin', '/v3/admin', '/v4/admin', '/v1.1/admin', '/v2.0/admin')):
            status, body = 200, b'version-confirmed'
        if '/method/' in path and self.command in ('get', 'post', 'put', 'head', 'options'):
            status, body = 200, b'method-confirmed'
        if '/hop/' in path:
            needed = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get('needed', ['Authorization'])[0]
            if needed not in h and not control: status, body = 200, b'stripped-at-proxy-confirmed'
        for kind in ('fallback', 'different', 'unavailable', 'head'):
            if '/' + kind + '/' in path and (control or path != '/' + kind + '/api/v1/admin'):
                status, body = (503 if kind == 'unavailable' and control else 200), b'fallback-response'
                if kind == 'different' and not control: body = b'different-resource' * 30
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=UTF-8')
        if '/head/' not in path: self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(body)
    do_GET = do_HEAD = do_POST = do_PUT = do_OPTIONS = handle_probe
    do_get = do_head = do_post = do_put = do_options = handle_probe
    def log_message(self, *args): pass

class Proxy(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    origin_port = None
    def handle_probe(self):
        nominated = {part.strip().lower() for part in self.headers.get('Connection', '').split(',')}
        headers = {k: v for k, v in self.headers.items() if k.lower() not in nominated | {'connection', 'proxy-connection'}}
        OBSERVED.append(dict(hop='proxy', method=self.command, path=self.path,
                             nomination=self.headers.get('Connection'), stripped=sorted(nominated),
                             keep=headers.get('X-Keep')))
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length) if length else None
        with contextlib.closing(http.client.HTTPConnection('127.0.0.1', self.origin_port, timeout=5)) as upstream:
            upstream.request(self.command, self.path, body=body, headers=headers)
            response = upstream.getresponse()
            data = response.read()
            self.send_response(response.status)
            for k, v in response.getheaders():
                if k.lower() not in {'connection', 'transfer-encoding', 'server', 'date'}: self.send_header(k, v)
            self.end_headers()
            if self.command != 'HEAD': self.wfile.write(data)
    do_GET = do_HEAD = do_POST = do_PUT = do_OPTIONS = handle_probe
    do_get = do_head = do_post = do_put = do_options = handle_probe
    def log_message(self, *args): pass

def start():
    origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    Proxy.origin_port = origin.server_port
    proxy = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    for server in (origin, proxy): threading.Thread(target=server.serve_forever, daemon=True).start()
    return origin, proxy

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('jar', type=pathlib.Path)
    parser.add_argument('evidence', type=pathlib.Path)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    origin, proxy = start()
    commands = []
    def call(name, argv, expected=0):
        for option in ('--protocol', '--playbooks', '--payload-set'):
            while argv.count(option) > 1:
                index = argv.index(option); argv = argv[:index] + argv[index + 2:]
        command = ['java', '-jar', str(args.jar.resolve())] + argv
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        commands.append(dict(name=name, command=command, exit=result.returncode))
        (args.evidence / (name + '.stdout')).write_text(result.stdout)
        (args.evidence / (name + '.stderr')).write_text(result.stderr)
        assert result.returncode == expected, (name, result.stderr)
        return result
    try:
        # Doctor and listing require no input and no network requests.
        call('doctor', ['--version'])
        (args.evidence / 'jar.sha256').write_text(hashlib.sha256(args.jar.read_bytes()).hexdigest() + '\n')
        listing = call('list-bypass', ['bypass', '--list-playbooks']).stdout
        hs_listing = call('list-sweep', ['sweep', '--list-playbooks']).stdout
        for item in IDS: assert item in listing and item in hs_listing
        assert 'HTTP/1 only' in listing
        with tempfile.TemporaryDirectory(prefix='bypass-playbooks-input-') as temporary:
            temporary = pathlib.Path(temporary)
            def scan(name, mode, path, ids, extras=(), method='GET'):
                raw = temporary / (name + '.raw')
                host = f'127.0.0.1:{proxy.server_port}'
                raw.write_bytes((f'{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: fixture\r\nCookie: session=fixture; preference=dark\r\nX-Api-Key: fixture\r\nX-Auth-Token: fixture\r\nX-Access-Token: fixture\r\nX-Keep: preserved\r\n\r\n').encode())
                base = [mode, '--request', str(raw), '--target-origin', 'http://' + host, '--playbooks', ','.join(ids),
                        '--protocol', 'http1', '--retry-attempts', '0', '--global-concurrency', '1', '--per-host-concurrency', '1', '--redact']
                if mode == 'sweep': base += ['--payload-set', 'high-signal']
                output = args.evidence / name
                call(name, base + ['--output', str(output)] + list(extras))
                rows = [json.loads(line) for line in (output / 'results.jsonl').read_text().splitlines()]
                summary = json.loads((output / 'summary.json').read_text())
                assert summary.get('state') == 'completed', summary
                assert summary['requestsSent'] == len(rows), (name, summary, len(rows))
                for row in rows:
                    assert (output / row['requestRef']).is_file()
                    if row.get('responseRef'): assert (output / row['responseRef']).is_file()
                return rows, output, base
            for index, (path, playbook) in enumerate(zip(['/forwarded/api/v1/admin', '/hop/api/v1/admin?needed=Authorization', '/referer/api/v1/admin', '/prefix/api/v1/admin', '/version/api/v1/admin', '/method/api/v1/admin'], IDS)):
                rows, _, _ = scan('check-' + str(index), 'bypass', path, [playbook], ['--api-prefix', '/private-api'])
                assert any(row.get('status') == 200 and not row['baseline'] for row in rows), playbook
                assert all(row.get('playbookId') == playbook for row in rows if not row['baseline'])
            # Same new entries are executable in both Sweep inventories.
            for inventory in ('high-signal', 'all'):
                rows, _, _ = scan('sweep-' + inventory, 'sweep', '/forwarded/api/v1/admin', [IDS[0]], ['--payload-set', inventory])
                assert any(row.get('status') == 200 and row.get('playbookId') == IDS[0] for row in rows)
            rows, _, _ = scan('both-hop', 'bypass', '/hop/api/v1/admin?needed=Authorization', [IDS[1]], ['--protocol', 'both'])
            hop_rows = [row for row in rows if row.get('playbookId') == IDS[1]]
            assert len(hop_rows) == 10 and all(row['protocol'] == 'http1' for row in hop_rows), hop_rows
            rows, output, base = scan('fallback', 'bypass', '/fallback/api/v1/admin', [IDS[3]])
            candidates = [row for row in rows if not row['baseline']]
            assert all(row['calibration']['assessment'] == 'MATCH' and row['signal'] == 'LIKELY_BYPASS' for row in candidates)
            assert all((output / row['calibration']['controlRequestRef']).is_file() for row in candidates)
            assert sum(row.get('controlRole') == 'WILDCARD' for row in rows) == 1
            for route, assessment in [('different', 'DIFFERENT'), ('unavailable', 'UNAVAILABLE'), ('head', 'UNAVAILABLE')]:
                rows, _, _ = scan(route, 'bypass', '/' + route + '/api/v1/admin', [IDS[3]], method='HEAD' if route == 'head' else 'GET')
                assert all(row['calibration']['assessment'] == assessment for row in rows if not row['baseline'])
            rows, _, _ = scan('calibration-off', 'bypass', '/fallback/api/v1/admin', [IDS[3]], ['--no-wildcard-calibration'])
            assert all(row.get('controlRole') != 'WILDCARD' and 'calibration' not in row for row in rows)
            rows, _, _ = scan('anonymous-context', 'sweep', '/fallback/api/v1/admin', [IDS[3]], ['--sweep-mode', 'authenticated', '--no-skip-likely-public', '--auth-cookie', 'session'])
            controls = [r for r in OBSERVED if r['hop'] == 'origin' and '__bf_control_' in r['path'] and '/fallback/' in r['path']]
            assert any(not r['hasAuthorization'] and r['hasCookie'] for r in controls)
            for enabled in (False, True):
                rows, out, _ = scan('verb-gate-' + str(enabled), 'sweep', '/method/api/v1/admin', [IDS[5]], ['--include-state-changing'] if enabled else [])
                methods = {(out / row['requestRef']).read_text().split()[0] for row in rows if not row['baseline']}
                assert ('post' in methods and 'put' in methods) == enabled
            before = len(OBSERVED)
            call('preview', base + ['--preview'])
            assert 'Runtime-generated wildcard' in (args.evidence / 'preview.stdout').read_text()
            call('preview-http2', base + ['--protocol', 'http2', '--playbooks', IDS[1], '--preview'])
            assert 'Unsupported with forced HTTP/2' in (args.evidence / 'preview-http2.stderr').read_text()
            call('invalid-playbook', base + ['--playbooks', 'missing'], 2)
            call('conflicting-family', base + ['--families', 'path', '--playbooks', IDS[0]], 2)
            call('invalid-prefix', base + ['--api-prefix', '//untrusted'], 2)
            job = temporary / 'job.yaml'
            job.write_text('schemaVersion: 1\nbypass:\n  playbooks: [bypass.path.api_prefix]\n  apiPrefixes: [/yaml-prefix]\n  wildcardCalibration: false\n')
            yaml_preview = call('yaml-preview', base[:5] + ['--config', str(job), '--preview']).stdout
            assert '/yaml-prefix' in yaml_preview and 'Runtime-generated wildcard' not in yaml_preview
            override = call('yaml-override', base[:5] + ['--config', str(job), '--api-prefix', '/flag-prefix', '--wildcard-calibration', '--preview']).stdout
            assert '/flag-prefix' in override and '/yaml-prefix' not in override and 'Runtime-generated wildcard' in override
            assert len(OBSERVED) == before, 'Previews or invalid configuration sent traffic'
            call('results-readback', ['results', '--input', str(output), '--format', 'jsonl'])
        assert any(row['hop'] == 'proxy' and 'authorization' in row['stripped'] for row in OBSERVED)
        assert any(row['hop'] == 'origin' and '/hop/' in row['path'] and not row['hasAuthorization'] for row in OBSERVED)
        (args.evidence / 'proof.json').write_text(json.dumps(dict(state='PASS', checks=IDS, twoHopStripping=True, calibration=['MATCH','DIFFERENT','UNAVAILABLE'], commands=len(commands)), indent=2))
    finally:
        (args.evidence / 'commands.json').write_text(json.dumps(commands, indent=2))
        (args.evidence / 'lab-observations.json').write_text(json.dumps(OBSERVED, indent=2))
        for server in (proxy, origin): server.shutdown(); server.server_close()

if __name__ == '__main__': main()
