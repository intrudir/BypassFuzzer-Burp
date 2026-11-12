# Evidence triage

Every successful run directory contains:

```text
run.json
results.jsonl
summary.json
requests/000001-request.raw
responses/000001-response.raw
```

`results.jsonl` records include sequence, mode, target, protocol, family,
payload, encoding, baseline flag, signal, retry attempt, status, length,
duration, error, and relative request/response references.

## Start with integrity and baselines

```bash
python3 scripts/bypassfuzzer.py triage evidence/run-001
```

The helper validates schema version, run ID, summary count, sequencing, safe
relative references, and referenced files. It prints baseline metadata first,
then at most 50 candidates with these default signals:

```text
LIKELY_BYPASS,IDOR_CANDIDATE,MASS_ASSIGNMENT_CANDIDATE,RESPONSE_CHANGED,THROTTLED,NO_RESPONSE
```

Options:

```bash
# Machine-readable report
python3 scripts/bypassfuzzer.py triage evidence/run-001 --json

# A chosen signal set
python3 scripts/bypassfuzzer.py triage evidence/run-001 \
  --signals LIKELY_BYPASS,RESPONSE_CHANGED

# Include every non-baseline mutation and remove the display cap
python3 scripts/bypassfuzzer.py triage evidence/run-001 --all --limit 0
```

Sweep uses descriptive signals such as `403 -> 200`, `Content-Type …`,
`Length +100`, and authenticated-workflow annotations. Default triage includes
nonempty Sweep signals as well; an explicit `--signals` uses only that set.

The helper reports status and length equality plus SHA-256 body equality against
the relevant target/protocol baselines. It never prints raw request or response
bodies. Open the printed paths only for candidates that require review.

## Signal meanings

- `BASELINE`: a control request, not a finding.
- `LIKELY_BYPASS`: a blocked `401/403` control changed to `2xx/3xx`.
- `IDOR_CANDIDATE`: an IDOR mutation passed a denied target control, or a response-guided path/body conflict returned the target value.
- `MASS_ASSIGNMENT_CANDIDATE`: the response reported the target identifier at the selected JSON pointer; persistence still needs readback.
- `RESPONSE_CHANGED`: the mode’s status/body comparison changed. Bypass uses status or a body-length delta of at least 100 bytes; IDOR also detects body differences against a successful target baseline.
- `THROTTLED`: the response used a configured throttle status.
- `NO_RESPONSE`: transport failed or no response was captured.
- `NO_SIGNAL`: the simple classifier saw no material delta.

These labels do not understand application semantics. Validate the response body,
identity, object ownership, server-side state, and reproducibility. For IDOR,
compare with both `idor.baseline.control` and `idor.baseline.target`. Review
`TARGET_BASELINE_2XX_REVIEW`, `TARGET_BASELINE_500_REVIEW`, and inconclusive baseline
signals before interpreting mutations; a baseline remains listed even when its
signal differs from `BASELINE`. Matching the
denied target is not a bypass.

Keep raw evidence private. Without `--redact`, stored requests and configuration
can contain credentials. With it, common credential headers are masked in stored
files but still sent over the wire.
