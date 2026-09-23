# BypassFuzzer CLI

The CLI runs Sweep, Bypass, IDOR, and URL Validation without Burp. Use it only against systems you are authorized to test. Imported Sweep destinations are treated as the authorized scope; redirects are never followed.

## Build and launch

```bash
./gradlew :cli:shadowJar
java -jar cli/build/libs/bypassfuzzer-cli.jar --help

docker build -t bypassfuzzer .
docker run --rm -v "$PWD:/work" bypassfuzzer sweep --urls /work/targets.txt --output /work/output
```

The Docker image is built locally from the same CLI source and is not published by the release workflow.

## Commands and inputs

Sweep accepts exactly one source:

```bash
bypassfuzzer sweep --urls targets.txt
bypassfuzzer sweep --request request.raw --target-origin https://app.example
bypassfuzzer sweep --request-manifest requests.yaml
bypassfuzzer sweep --openapi openapi.yaml --base-url https://app.example
bypassfuzzer sweep --postman collection.json
bypassfuzzer sweep --retry-package bypassfuzzer-retry-queue.json
```

A request manifest is a YAML list, or an object with a `requests` list:

```yaml
requests:
  - requestFile: requests/admin.raw
    targetOrigin: https://app.example
```

Request-file paths are relative to the manifest. `targetOrigin` contains only scheme, host, and optional port and is always the actual network destination. The raw request target and Host header remain fuzzable data.

Sweep defaults to `--payload-set high-signal`. Use `--payload-set all` for all twelve Bypass families. `--families` filters the selected inventory; all-payload IDs are `header,path,verb,param,cookie,trailingdot,trailingslash,extension,contenttype,encoding,protocol,case`. State-changing OpenAPI/Postman operations are excluded unless `--include-state-changing` is present.

Targeted examples:

```bash
bypassfuzzer bypass --request blocked.raw --target-origin https://app.example --families header,path,verb
bypassfuzzer idor --request object.raw --target-origin https://app.example --authorized-id 100 --target-id 200 --id-location path:3 --preview
bypassfuzzer url-validation --request redirect.raw --target-origin https://app.example \
  --marker '{INJECT}' --allowed-host trusted.example --attacker-host attacker.example \
  --contexts absolute-url,host-header,cors --encodings raw,intruders
```

Collaborator is intentionally unavailable. No CLI option or YAML key enables it.

IDOR discovers exact identifier slots in path segments, query/form values, JSON fields, plain text, XML text/attributes, multipart text fields, selected header values, and selected cookie values. Select a slot with `--id-location` when the authorized value appears more than once. Credential-bearing and structural headers/cookies are excluded. `--preview` sends no traffic. Every applicable mutation from enabled IDOR playbooks is planned, with no numeric cap; `--max-probes` and YAML `execution.maxProbes` are rejected for IDOR. Execution is serial by default. For create requests, `--unique-json-field /name` gives each planned request a distinct JSON string value.

The `idor.body.response_guided_mass_assignment` family is enabled by default. It searches both live baseline JSON responses for exact values matching either configured identifier, derives JSON body fields from those paths, and tests both an authorized path with the target ID in the body and a target path with the authorized ID in the body. To preview those requests offline, save a raw HTTP response and add `--baseline-response baseline.raw`; without it, the family is planned only after live baselines return. Select a different `idor.families` list in YAML or `--families` on the command line to exclude it. Results are candidates for manual readback, not proof that a write persisted or granted access.

`idor.hybrid.paired_control_separators` is enabled by default. It combines only the two selected IDs in both directions, with LF, CRLF, CR, NUL, and tab first. It covers Unicode Cc controls and a bounded set of invisible format characters, encoded for the selected slot. The preview reports planned/eligible counts and unsupported-context notes. Header values use only inline tab with `--protocol http1`; cookie values and HTTP/2 or auto-negotiated headers receive no control probes.

The DANGEROUS IDOR families `idor.query.numeric_pivots`, `idor.path.special_identifier_values`, `idor.body.json_edge_cases`, `idor.hybrid.canonical_identifier_formats`, and `idor.hybrid.truncated_identifier_variants` are disabled by default. They can probe numeric values such as `0`, `1`, and `-1`, nearby IDs, or shortened IDs beyond the two you entered. Select a family explicitly with `--families` or an explicit `idor.families` YAML list to opt in; the CLI warns on stderr. Use `--preview` first to inspect the generated requests. Bypass defaults are unaffected.

## Protocols and execution

`--protocol auto` is the default. HTTPS negotiates HTTP/2 or HTTP/1 with ALPN; cleartext auto uses HTTP/1. `http2` forces native HTTP/2 (h2c prior knowledge for cleartext), while `both` runs each applicable baseline and probe over HTTP/1.1 and HTTP/2. Protocol-family payloads may deliberately override the run protocol.

Useful shared options include:

```text
--proxy http://[user:pass@]proxy:8080
--insecure
--connect-timeout 10
--request-timeout 15
--global-concurrency 10
--per-host-concurrency 10
--throttle-codes 429,503
--posture ride-hard|conservative
--pause-mode off|fixed|smart
--fixed-pause-ms 30000
--retry-attempts 1
--header 'Authorization: Bearer ...'
--user-agent-mode disabled|synthetic|browser-like
```

## YAML jobs

Every command accepts `--config job.yaml`. Command-line flags replace YAML values. Relative paths resolve from the YAML file.

```yaml
schemaVersion: 1
input:
  request: requests/admin.raw
  targetOrigin: https://app.example
transport:
  protocol: auto
  requestTimeoutSeconds: 15
execution:
  globalConcurrency: 10
  perHostConcurrency: 5
  throttleStatusCodes: [429, 503]
  retryAttempts: 1
  maxProbes: 500
  posture: ride-hard
  pauseMode: smart
evidence:
  output: output/admin-run
  redact: false
bypass:
  families: [header, path, verb]
  fuzzExistingCookies: false
```

Use the appropriate `sweep`, `bypass`, `idor`, or `urlValidation` section. Unknown keys fail validation, and any key containing `collaborator` is rejected.

## Output and exit status

Each run writes `run.json`, `results.jsonl`, `summary.json`, and numbered raw request/response files. JSONL is also streamed to stdout; human progress is written to stderr. Evidence permissions are owner-only where the filesystem supports POSIX permissions.

Full wire evidence is stored by default and can contain credentials. `--redact` masks common credential headers in stored requests, responses, and configuration without changing what is sent.

The exit code is `0` once a scan starts, including runs with findings, per-request failures, cancellation, or a finalized failed summary. Usage, YAML, input, and other preflight failures return `2`; automation should read `summary.json` for scan state and findings.
