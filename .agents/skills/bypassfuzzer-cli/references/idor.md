# IDOR / BOLA

Use IDOR with two different controlled identifiers:

- `--authorized-id`: an exact literal present in the captured request and owned
  by the authenticated test identity.
- `--target-id`: a different controlled object or account that the same identity
  should not access.

```bash
python3 scripts/bypassfuzzer.py run idor \
  --request object.raw \
  --target-origin https://api.example \
  --authorized-id 100 \
  --target-id 200 \
  --output evidence/idor-001
```

Preflight fails if the identifiers are empty, equal, or the authorized literal
does not occur in the request.

## Baseline order

The first two records for each target/protocol are:

1. `idor.baseline.control`: the original authorized identifier.
2. `idor.baseline.target`: the direct target identifier.

Playbooks then explore path, query, body, and hybrid variants. A
`RESPONSE_CHANGED` result is often only a difference from the authorized control;
it may still match the denied-target baseline exactly. Use the triage helper's
status, length, and body-hash comparisons against both baselines.

Confirm IDOR only when a controlled unauthorized object's data or action is
observed. Status similarity is insufficient. Avoid enumeration and use the
minimum second-account or second-tenant data needed to prove the boundary.

## Slots, playbooks and create requests

`--id-location` selects an exact discovered slot when the authorized literal
occurs more than once: `path:3`, `json:/account/id`, `header:x-object-id#0`,
`multipart:id#0`, and query/form/XML/plain-text/cookie slots are supported.
Credential and structural headers/cookies are excluded. Inspect discovery and
planned requests with `--preview`. IDOR plans all applicable enabled mutations;
`--max-probes` and YAML `execution.maxProbes` fail preflight.

The default `idor.body.response_guided_mass_assignment` playbook derives fields
from both live JSON baselines. For an offline preview supply a saved raw HTTP
response with `--baseline-response`; without it these probes require live
baselines. `--unique-json-field /name` gives each planned create request a unique
JSON string field. `--include-method-changes` adds method/override variants.

`idor.hybrid.paired_control_separators` combines the two supplied IDs in both
directions, with LF/CRLF/CR/NUL/tab and bounded Unicode controls. Header slots
allow inline tab only with HTTP/1; cookie and HTTP/2/auto header slots omit these
probes. Preview reports eligible/planned counts and unsupported-context notes.

The DANGEROUS playbooks `idor.query.numeric_pivots`,
`idor.path.special_identifier_values`, `idor.body.json_edge_cases`,
`idor.hybrid.canonical_identifier_formats`, and
`idor.hybrid.truncated_identifier_variants` are disabled by default. Explicit
`--families` or YAML `idor.families` opts into values outside the two entered
IDs; keep that choice within the authorized test data. A target-baseline 500 is
marked `TARGET_BASELINE_500_REVIEW` and still permits mutations after a successful
authorized control. Response-guided writes require independent readback.
