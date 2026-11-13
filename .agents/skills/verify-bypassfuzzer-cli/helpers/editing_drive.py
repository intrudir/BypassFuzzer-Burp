#!/usr/bin/env python3
"""Packaged pause/edit/resume proof, using only an owned loopback fixture."""
import argparse, hashlib, http.server, json, os, pathlib, subprocess, threading, time


def wait_for(read, predicate, timeout=25):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
            if predicate(last):
                return last
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(.03)
    raise AssertionError(f'timed out: {last}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--jar', type=pathlib.Path, required=True)
    parser.add_argument('--evidence', type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    observed, processes, proofs = [], [], []
    lock = threading.Lock()

    class Lab(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def __getattr__(self, name):
            if name.startswith('do_'):
                return self.reply
            raise AttributeError(name)

        def reply(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            row = dict(time=time.time(), method=self.command, path=self.path,
                       headers=dict(self.headers), body=body.decode('utf-8', 'replace'))
            with lock:
                observed.append(row)
            time.sleep(.09)
            path = self.path.split('?', 1)[0]
            status = 403 if path in ['/private', '/sweep-one', '/sweep-two', '/objects/222'] else 200
            payload = b'{"id":"111","name":"owned fixture"}' if path == '/objects/111' else b'owned pause/edit/resume fixture'
            self.send_response(status)
            self.send_header('Content-Type', 'application/json' if path.startswith('/objects/') else 'text/plain')
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Connection', 'close')
            self.end_headers()
            if self.command.upper() != 'HEAD':
                self.wfile.write(payload)

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Lab)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    origin = f'http://127.0.0.1:{port}'
    status_paths = []
    try:
        for mode in ['bypass', 'sweep', 'idor', 'url-validation']:
            folder = args.evidence / mode
            folder.mkdir()
            control = folder / 'control.txt'
            control.write_text('pause')
            control.chmod(0o600)
            status_file = control.with_name(control.name + '.status.json')
            status_paths.append(status_file)
            source = folder / 'request.raw'
            target = '/objects/111' if mode == 'idor' else '/validate?url={INJECT}' if mode == 'url-validation' else '/private'
            source.write_text(f'GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer fixture-only\r\n\r\n', newline='')
            flags = ['--request', str(source), '--target-origin', origin]
            initial = ['bypass.header.forwarded']
            selected = ['bypass.path.api_prefix']
            if mode == 'sweep':
                urls = folder / 'urls.txt'
                urls.write_text(f'http://localhost:{port}/sweep-one\n{origin}/sweep-two\n')
                flags = ['--urls', str(urls), '--playbooks', 'bypass.path.api_prefix', '--max-probes', '80']
                initial, selected = ['bypass.path.api_prefix'], ['bypass.header.forwarded']
            elif mode == 'idor':
                flags += ['--authorized-id', '111', '--target-id', '222', '--families', 'idor.path.suffix_formats']
                initial, selected = ['idor.path.suffix_formats'], ['idor.hybrid.identifier_encoding']
            elif mode == 'url-validation':
                flags += ['--attacker-host', 'callback.invalid', '--allowed-host', 'allowed.invalid',
                          '--contexts', 'absolute_url', '--attacks', 'domain_allow_list_bypass']
                initial = ['url.context.ABSOLUTE_URL', 'url.attack.DOMAIN_ALLOW_LIST_BYPASS']
                selected = ['url.context.ABSOLUTE_URL', 'url.attack.IPV6']
            else:
                flags += ['--playbooks', initial[0]]
            if mode in ['bypass', 'sweep']:
                for i in range(18):
                    flags += ['--api-prefix', f'/owned-{i}']
            command = ['java', '-jar', str(args.jar), mode, *flags, '--output', str(folder / 'scan'),
                       '--control-file', str(control), '--header', 'User-Agent: Before-edit-fixture',
                       '--global-concurrency', '2', '--per-host-concurrency', '2', '--retry-attempts', '0', '--redact']
            (folder / 'command.json').write_text(json.dumps(command, indent=2))
            with lock:
                start = len(observed)
            with (folder / 'stdout.log').open('w') as stdout, (folder / 'stderr.log').open('w') as stderr:
                process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
                processes.append(process)
                state = lambda: json.loads(status_file.read_text())
                wait_for(state, lambda s: s['state'] == 'paused')
                with lock:
                    assert len(observed) == start, 'initial pause sent traffic'
                control.write_text('resume')
                wait_for(lambda: len(observed) - start, lambda count: count >= 3)
                control.write_text('pause')
                paused = wait_for(state, lambda s: s['state'] == 'paused')
                with lock:
                    boundary = len(observed)
                control.write_text(json.dumps(dict(action='apply-resume', expectedRevision=0,
                                                  commandId='invalid', configuration=dict(playbooks=['unknown.playbook']))))
                rejected = wait_for(state, lambda s: bool(s['error']))
                assert rejected['revision'] == 0 and rejected['state'] == 'paused'
                with lock:
                    assert len(observed) == boundary, 'invalid edit sent traffic'
                edit = dict(excludeHosts=['localhost'] if mode == 'sweep' else [], concurrency=2,
                            perHostConcurrency=1, requestsPerSecond=20, playbooks=selected,
                            headers=['User-Agent: After-edit-fixture', 'X-Edited: fixture-only'],
                            removeHeaders=['Authorization'])
                control.write_text(json.dumps(dict(action='apply-resume', expectedRevision=0,
                                                  commandId='edit-1', configuration=edit)))
                accepted = wait_for(state, lambda s: s['revision'] == 1 and s['error'] == '')
                process.wait(timeout=50)
                assert process.returncode == 0, (folder / 'stderr.log').read_text()
            summary = json.loads((folder / 'scan/summary.json').read_text())
            assert summary['state'] == 'completed', summary
            rows = [json.loads(line) for line in (folder / 'scan/results.jsonl').read_text().splitlines()]
            after = [row for row in rows if row.get('configurationRevision') == 1]
            assert after, (mode, summary)
            with lock:
                requests = list(observed[start:])
                new_wire = list(observed[boundary:])
            assert new_wire, mode
            assert all(r['headers'].get('User-Agent') == 'After-edit-fixture' and
                       r['headers'].get('X-Edited') == 'fixture-only' and
                       'Authorization' not in r['headers'] for r in new_wire), new_wire
            if mode == 'sweep':
                assert all(not r['headers'].get('Host', '').startswith('localhost:') for r in new_wire)
            assert summary['requestsSent'] == len(requests), (summary, len(requests))
            if mode == 'sweep':
                assert summary['plannedRequests'] == summary['completedRequests'], summary
            for row in rows:
                request = folder / 'scan' / row['requestRef']
                assert request.is_file()
                if row.get('responseRef'):
                    assert (folder / 'scan' / row['responseRef']).is_file()
                if row.get('configurationRevision') == 1:
                    text = request.read_text()
                    assert 'User-Agent: After-edit-fixture' in text
                assert request.stat().st_mode & 0o777 == 0o600
            assert status_file.stat().st_mode & 0o777 == 0o600
            assert 'fixture-only' not in status_file.read_text(), 'status leaked header values'
            config = json.loads((folder / 'scan/configuration-1.json').read_text())
            assert set(config['playbooks']) == set(selected)
            assert config['concurrency'] == 2 and config['perHostConcurrency'] == 1 and config['requestsPerSecond'] == 20
            assert 'fixture-only' not in json.dumps(config)
            (folder / 'wire.json').write_text(json.dumps(requests, indent=2))
            (folder / 'accepted.json').write_text(json.dumps(accepted, indent=2))
            (folder / 'rejected.json').write_text(json.dumps(rejected, indent=2))
            proofs.append(dict(mode=mode, state='PASS', initialPause=True, drainedPause=paused['inFlight'] == 0,
                               rejectedEditNoTraffic=True, revision=1, requests=len(requests), newRequests=len(new_wire),
                               scopeApplied=True, headersApplied=True, playbooksChanged=True, rawEvidenceRead=True))
        # Exact saved work has its own inventory, including legacy groups without catalog IDs.
        folder = args.evidence / 'replay'
        folder.mkdir()
        control = folder / 'control.txt'
        control.write_text('pause')
        control.chmod(0o600)
        entries = []
        for group, playbook in [('A', 'bypass.path.api_prefix'), ('B', 'bypass.header.forwarded'), ('legacy', '')]:
            for i in range(12):
                path = f'/saved/{group}/{i}'
                entries.append(dict(targetLabel='owned replay', payload=f'{group}-{i}', payloadFamily=group,
                                    payloadEncoding='', retryAttempt=0, requestRaw=f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n',
                                    url=origin + path, method='GET', httpMode='HTTP_1', payloadLabel=f'{group}-{i}',
                                    playbookId=playbook, controlRole='NONE'))
        package = folder / 'retry.json'
        package.write_text(json.dumps(dict(version='1', type='bypassfuzzer-retry-queue', entries=entries)))
        command = ['java', '-jar', str(args.jar), 'sweep', '--retry-package', str(package),
                   '--output', str(folder / 'scan'), '--control-file', str(control), '--retry-attempts', '0',
                   '--global-concurrency', '2', '--per-host-concurrency', '2']
        (folder / 'command.json').write_text(json.dumps(command, indent=2))
        with lock:
            start = len(observed)
        with (folder / 'stdout.log').open('w') as stdout, (folder / 'stderr.log').open('w') as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr)
            processes.append(process)
            state = lambda: json.loads(control.with_name(control.name + '.status.json').read_text())
            wait_for(state, lambda row: row['state'] == 'paused')
            assert any(key.startswith('saved.') for key in state()['availablePlaybooks'])
            control.write_text('resume')
            wait_for(lambda: len(observed) - start, lambda count: count >= 3)
            control.write_text('pause')
            wait_for(state, lambda row: row['state'] == 'paused')
            with lock:
                boundary = len(observed)
            edit = dict(action='apply-resume', expectedRevision=0, commandId='replay-edit',
                        configuration=dict(playbooks=['bypass.header.forwarded'], concurrency=2,
                                           perHostConcurrency=1, requestsPerSecond=20,
                                           headers=['User-Agent: Edited-replay']))
            control.write_text(json.dumps(edit))
            wait_for(state, lambda row: row['revision'] == 1)
            process.wait(timeout=40)
            assert process.returncode == 0
        with lock:
            after = list(observed[boundary:])
            wire = list(observed[start:])
        assert len(after) == 12 and all(row['path'].startswith('/saved/B/') and row['headers'].get('User-Agent') == 'Edited-replay' for row in after), after
        rows = [json.loads(line) for line in (folder / 'scan/results.jsonl').read_text().splitlines()]
        assert len(rows) == len(wire) and all(row['controlRole'] == 'NONE' for row in rows)
        assert all(row['playbookId'] == 'bypass.header.forwarded' and row['headerRevision'] == 1 for row in rows if row['configurationRevision'] == 1)
        assert json.loads((folder / 'scan/summary.json').read_text())['requestsSent'] == len(wire)
        assert not json.loads((folder / 'scan/retry-queue.json').read_text())['entries']
        (folder / 'wire.json').write_text(json.dumps(wire, indent=2))
        replay_proof = dict(state='PASS', exactInventory=True, legacyGroupsSelectable=True,
                            disabledRequestsUnsent=True, headersApplied=True, noCalibrationAdded=True)
        result = dict(state='PASS', artifactSHA256=hashlib.sha256(args.jar.read_bytes()).hexdigest(), modes=proofs, replay=replay_proof)
        (args.evidence / 'assertions.json').write_text(json.dumps(result, indent=2))
        print('PASS packaged pause/edit/resume: scope, throttle, playbooks, headers and evidence in all four attack modes')
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        server.shutdown()
        server.server_close()
        (args.evidence / 'cleanup.json').write_text(json.dumps(dict(state='PASS', ownedProcessesStopped=True,
                                                                  ownedFixtureStopped=True), indent=2))


if __name__ == '__main__':
    main()
