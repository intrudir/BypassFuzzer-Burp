# Coverage Sweep

Use Sweep for broad, bounded coverage across a scoped endpoint set. It sends a
baseline and a bounded high-signal inventory, or the complete uncapped inventory.

## Choose exactly one input

- `--urls targets.txt`: one absolute HTTP(S) URL per line.
- `--request request.raw --target-origin ORIGIN`: one exact raw request.
- `--request-manifest requests.yaml`: a list of raw request files and origins.
- `--openapi FILE_OR_HTTPS_URL [--base-url ORIGIN]`: OpenAPI 3 or Swagger 2.
- `--postman collection.json [--base-url ORIGIN]`: Postman v2.0/v2.1.
- `--retry-package package.json`: a Burp Sweep version-1 retry package.

URL lists do not contain authentication. Add scoped headers or use raw requests
or a protected YAML job when authentication is required.

## Payload sets

`high-signal` is the default bounded inventory. Its filter names are:

```text
Matrix / Extension
Extension / Negotiation
Path Normalization
Encoding
Debug Params
Content-Type
Header
Host Parsing
Verb
```

`all` uses the complete shared Bypass planner and rejects `--max-probes` or
YAML `execution.maxProbes`. Its family IDs are:

```text
header,path,verb,param,cookie,trailingdot,trailingslash,extension,contenttype,encoding,protocol,case
```

Use exact high-signal display names or all-payload IDs with `--families`. For exact check selection and calibration, read [playbooks.md](playbooks.md). High signal Verb post/put probes also require `--include-state-changing`.

## Examples

Start with the normal high-signal cap:

```bash
python3 scripts/bypassfuzzer.py run sweep \
  --urls targets.txt \
  --payload-set high-signal \
  --output evidence/sweep-001
```

Run selected full-planner families:

```bash
python3 scripts/bypassfuzzer.py run sweep \
  --request blocked.raw \
  --target-origin https://app.example \
  --payload-set all \
  --families header,path,encoding \
  --output evidence/sweep-002
```

OpenAPI and Postman inputs include only `GET`, `HEAD`, and `OPTIONS` by default.
Supply `--include-state-changing` only when those imported operations and their
test data are within the authorized run.

Interpret Sweep as prioritization. A blocked baseline becoming successful is a
candidate; verify the response represents the protected resource or capability
and is not a public route, redirect, generic error, or cache artifact.

## Workflow and import controls

`--sweep-mode blocked|authenticated|imported` selects the same workflow as Burp.
Authenticated workflows can strip selected `--auth-header` / `--auth-cookie`
values, verify unauthenticated access, and skip likely-public responses. Use
`--[no-]verify-unauthenticated-access` and `--[no-]skip-likely-public` when changing
those choices. Candidate controls include `--max-candidates` (100 by default),
`--[no-]dedupe-endpoints`, `--[no-]exclude-static-assets`, repeatable
`--exclude-host`, and `--host-ports` for Host-parsing probes. Retry packages replay
their exact retained requests and destinations; inspect their scope before replay.

OpenAPI defaults to `--openapi-parameter-policy required-variables`. Missing
required values stop the import before target traffic. Supply repeated
`--openapi-variable NAME=VALUE`; values may contain `=`. Only included operations
must have their variables resolved. Available policies:

```text
source-values-only,required-empty,required-variables,all-empty,all-variables,sample-values
```

`--openapi-fill-examples` fills blank/unset values from examples or shared sample
suggestions while preserving explicit values. Use `--no-openapi-fill-examples`
to override YAML. These options require OpenAPI input. Inspect a safe preview:

```bash
python3 scripts/bypassfuzzer.py run sweep --openapi api.yaml \
  --openapi-variable tenantId=123 --openapi-variable accountId=456 --preview
```

YAML puts `openapiParameterPolicy`, `openapiVariables` (a scalar value map) and
`openapiFillExamples` under `input`. CLI variables override matching YAML names
and keep other YAML variables. Local specification paths resolve from the YAML
file; HTTP(S) locations remain URLs.
