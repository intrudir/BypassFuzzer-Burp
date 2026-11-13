# Common CLI contract

## Captured requests and routing

Bypass, IDOR, URL Validation, and raw-request Sweep input use an exact HTTP
request file plus a separate origin:

```http
GET /admin/reports HTTP/1.1
Host: app.example
Authorization: Bearer test-token

```

```bash
python3 scripts/bypassfuzzer.py run bypass \
  --request blocked.raw \
  --target-origin https://app.example \
  --output evidence/bypass-001
```

The origin contains only scheme, host, and optional port. It controls the
network destination even when a mutation changes `Host` or the request target.
Raw requests retain ordered duplicate headers and bodies.

## Native defaults

Unless the operator or rules of engagement require overrides, retain the CLI's
defaults:

| Setting | Default |
|---|---|
| Protocol | `auto` |
| Connect/request timeout | 10 / 15 seconds |
| Global/per-host concurrency | 1 / up to 1 |
| Throttle status codes | `429,503` |
| Retries | Bypass/Sweep 3; IDOR 1; URL Validation 0 |
| High-signal Sweep mutation cap | 350 per input; up to 100 candidates |
| Other mutation caps | Bypass/URL Validation uncapped by default; full-catalog Sweep and IDOR reject a numeric cap |
| Posture / pause mode | `ride-hard` / `off` |
| User-Agent variation | disabled |
| Evidence redaction | disabled |

Useful overrides include `--protocol http1|http2|both`, `--proxy`, `--insecure`,
`--global-concurrency`, `--per-host-concurrency`, `--max-probes` where supported,
`--posture conservative`, `--pause-mode smart`, `--retry-attempts`, repeatable
`--header`, and `--redact`. Use `--insecure` only for an intentionally
untrusted certificate in scope.

Do not place secrets in command arguments when a protected raw request or YAML
job can carry them. Keep input, configuration, and evidence inside the
engagement workspace with restrictive permissions. `--redact` masks common
credential headers only in stored evidence; the real values are still sent.

Protocol-family HTTP/0.9 probes preserve a versionless, headerless request line. Configured headers and fixed or randomized User-Agent values apply only to request formats that support headers. The HTTP/0.9 probe remains in Bypass and All payloads Sweep; other protocol probes retain configured header values and intentional payload deltas.

## YAML jobs

All modes accept a strict version-1 YAML job through `--config`. Flag values
override YAML, and YAML overrides the built-in defaults. Relative paths resolve
from the YAML file. Unknown keys and any key containing `collaborator` are
rejected.

Use the applicable `sweep`, `bypass`, `idor`, or `urlValidation` section. Prefer
YAML when a repeatable engagement job has many transport, concurrency, header,
or evidence settings. Protect YAML containing credentials like the raw request.

## Output and process contract

- Use a fresh or empty `--output` directory. A nonempty output directory is
  rejected before retained evidence is overwritten.
- Results stream as JSONL on stdout. Progress and the final human summary go to
  stderr.
- Usage, input, and configuration failures exit `2` before a run starts.
- Once evidence creation begins, inspect `summary.json`; process exit `0` does
  not mean there were no transport errors or findings.
- The helper propagates the CLI exit status and does not rewrite options. Its own resolution or
  integrity failures exit `1`. Preview creates no scan evidence.

See [runtime-results.md](runtime-results.md) for offline previews, run control,
Dashboard-style traffic limits and native result exports.

TLS checks the certificate chain and the hostname from the socket origin, including HTTP/0.9; a mutated Host header does not change that identity. `--insecure` explicitly disables these checks. Response bodies are capped at 64 MiB. HTTP/0.9 replies have no status line: a nonempty body uses a synthetic 200, while empty EOF is a transport error.
