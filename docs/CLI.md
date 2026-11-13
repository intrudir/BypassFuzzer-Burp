# BypassFuzzer CLI

The CLI runs Sweep, Bypass, IDOR, and URL Validation without Burp. Use it only against systems you are authorized to test. Imported Sweep destinations are treated as the authorized scope; redirects are never followed.

The repository-owned [CLI agent skill](../.agents/skills/bypassfuzzer-cli/SKILL.md)
provides mode-specific operating guidance, a compatibility doctor, and evidence triage.

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

### OpenAPI parameter controls

OpenAPI imports use the same policies and managed variables as Burp Sweep. The default is `required-variables`: missing required values stop the run before any target request is sent, instead of silently substituting generated IDs. Only enabled HTTP operations must have their variables resolved.

```bash
bypassfuzzer sweep --openapi openapi.yaml --preview \
  --openapi-variable tenantId=123 --openapi-variable accountId=456
```

`--openapi-parameter-policy` accepts `source-values-only`, `required-empty`, `required-variables`, `all-empty`, and `all-variables`. Explicit `sample-values` retains generated-sample import behavior. Variables override matching source values; repeat `--openapi-variable NAME=VALUE` for each value. Values may contain `=`. Use `--openapi-fill-examples` for Burp's “Fill empty with examples” behavior: it fills only blank/unset values with unambiguous examples/defaults or shared generated suggestions and keeps explicit values.

The same controls work in YAML; command-line variables override matching names and keep other YAML variables:

```yaml
schemaVersion: 1
input:
  openapi: specs/api.yaml
  openapiParameterPolicy: required-variables
  openapiVariables:
    tenantId: 123
    accountId: 456
  openapiFillExamples: false
```

Local YAML OpenAPI paths resolve relative to the job file. HTTP(S) specification URLs remain URLs. The parameter controls require an OpenAPI input; they do not change Postman or raw-request imports.

Targeted examples:

```bash
bypassfuzzer bypass --request blocked.raw --target-origin https://app.example --families header,path,verb
bypassfuzzer idor --request object.raw --target-origin https://app.example --authorized-id 100 --target-id 200 --id-location path:3 --preview
bypassfuzzer url-validation --request redirect.raw --target-origin https://app.example \
  --marker '{INJECT}' --allowed-host trusted.example --attacker-host attacker.example \
  --contexts absolute-url,host-header,cors --encodings raw,intruders
```

Native Burp Collaborator client creation is host-specific. Supply an operator-controlled callback domain with `--oob-domain` or an executable `--oob-generator` for the shared out-of-band payload inventory. A bare Collaborator-enable YAML key is rejected.

IDOR discovers exact identifier slots in path segments, query/form values, JSON fields, plain text, XML text/attributes, multipart text fields, selected header values, and selected cookie values. Select a slot with `--id-location` when the authorized value appears more than once. Credential-bearing and structural headers/cookies are excluded. `--preview` sends no traffic. Every applicable mutation from enabled IDOR playbooks is planned, with no numeric cap; `--max-probes` and YAML `execution.maxProbes` are rejected for IDOR. A target baseline of HTTP 500 is marked `TARGET_BASELINE_500_REVIEW` and still allows mutations after a successful authorized control; successful mutations are candidates for manual review. Execution is serial by default. For create requests, `--unique-json-field /name` gives each planned request a distinct JSON string value.

The `idor.body.response_guided_mass_assignment` family is enabled by default. It searches both live baseline JSON responses for exact values matching either configured identifier, derives JSON body fields from those paths, and tests both an authorized path with the target ID in the body and a target path with the authorized ID in the body. To preview those requests offline, save a raw HTTP response and add `--baseline-response baseline.raw`; without it, the family is planned only after live baselines return. Select a different `idor.families` list in YAML or `--families` on the command line to exclude it. Results are candidates for manual readback, not proof that a write persisted or granted access.

`idor.hybrid.paired_control_separators` is enabled by default. It combines only the two selected IDs in both directions, with LF, CRLF, CR, NUL, and tab first. It covers Unicode Cc controls and a bounded set of invisible format characters, encoded for the selected slot. The preview reports planned/eligible counts and unsupported-context notes. Header values use only inline tab with `--protocol http1`; cookie values and HTTP/2 or auto-negotiated headers receive no control probes.

The DANGEROUS IDOR families `idor.query.numeric_pivots`, `idor.path.special_identifier_values`, `idor.body.json_edge_cases`, `idor.hybrid.canonical_identifier_formats`, and `idor.hybrid.truncated_identifier_variants` are disabled by default. They can probe numeric values such as `0`, `1`, and `-1`, nearby IDs, or shortened IDs beyond the two you entered. Select a family explicitly with `--families` or an explicit `idor.families` YAML list to opt in; the CLI warns on stderr. Use `--preview` first to inspect the generated requests. Bypass defaults are unaffected.

## Protocols and execution

`--protocol auto` is the default. HTTPS negotiates HTTP/2 or HTTP/1 with ALPN; cleartext auto uses HTTP/1. `http2` forces native HTTP/2 (h2c prior knowledge for cleartext), while `both` runs each applicable baseline and probe over HTTP/1.1 and HTTP/2. Protocol-family payloads may deliberately override the run protocol.

HTTP/0.9 protocol-family probes retain their versionless, headerless wire format. Configured headers and User-Agent randomization are applied to header-supporting formats. The HTTP/0.9 probe remains available in Bypass and All payloads Sweep.

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

Retained `results` views hide calibration controls by default; add `--show-calibration` to include them. This changes the filtered display/export only: raw scan JSONL, exchanges and accounting remain complete. Smart filter repeat limits exclude controls from the candidate budget. Original, authorized and target baselines remain visible; records without control metadata retain their legacy behavior.


Transport and export safety: TLS verifies both the trusted chain and the socket-origin hostname unless `--insecure` is explicit. HTTP/0.9 uses the same 64 MiB response limit, rejects EOF before any body bytes, and represents nonempty body-only replies with a synthetic 200 because the protocol has no status line. `results --output` rejects the input evidence file and its file aliases before opening the sink; choose a different output file.

Authenticated Sweep's anonymous verification uses the current protocol pass, including independent HTTP/1 and HTTP/2 decisions under BOTH. Recovered mutations recompute their signals, finding counts and calibration metadata from retained comparison context. Original and calibration controls remain controls when retried. The reproducible packaged proof is `verify-bypassfuzzer-cli/helpers/verify.sh drive <fresh-run-id> boundaries` (see its feature map for fixture prerequisites).
