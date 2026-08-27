# BypassFuzzer CLI

The CLI runs Sweep, Bypass, IDOR, and URL Validation without Burp. Use it only against systems you are authorized to test. Imported Sweep destinations are treated as the authorized scope; redirects are never followed.

## Build and launch

```bash
./gradlew :cli:shadowJar :cli:distZip
java -jar cli/build/libs/bypassfuzzer-cli.jar --help

docker build -t bypassfuzzer .
docker run --rm -v "$PWD:/work" bypassfuzzer sweep --urls /work/targets.txt --output /work/output
```

Release images are published as `ghcr.io/intrudir/bypassfuzzer:<version>` and `:latest`.

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
bypassfuzzer idor --request object.raw --target-origin https://app.example --authorized-id 100 --target-id 200
bypassfuzzer url-validation --request redirect.raw --target-origin https://app.example \
  --marker '{INJECT}' --allowed-host trusted.example --attacker-host attacker.example \
  --contexts absolute-url,host-header,cors --encodings raw,intruders
```

Collaborator is intentionally unavailable. No CLI option or YAML key enables it.

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
