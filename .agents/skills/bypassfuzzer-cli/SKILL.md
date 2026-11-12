---
name: bypassfuzzer-cli
description: Operate BypassFuzzer CLI for authorized coverage sweeps, targeted authorization-bypass mutation, IDOR/BOLA testing, and URL-validation fuzzing. Use when the user names BypassFuzzer or asks to automate these request-mutation workflows with its CLI; use vulnerability-specific methodology for interpreting the resulting evidence.
metadata:
  source: BypassFuzzer CLI
  minimum-version: 1.4.4
  evidence-schema: 1
---

# BypassFuzzer CLI

Use BypassFuzzer to turn an already scoped HTTP target or captured request into
bounded mutation evidence. It is a testing tool, not a vulnerability verdict.

## Route to one mode

Read only the reference for the requested operation:

- Broad coverage across one or more endpoints: [references/sweep.md](references/sweep.md)
- One blocked request and authorization-bypass mutations: [references/bypass.md](references/bypass.md)
- Exact Bypass/Sweep playbook selection and fallback calibration: [references/playbooks.md](references/playbooks.md)
- Cross-user or cross-tenant object access: [references/idor.md](references/idor.md)
- URL parser or allow-list behavior: [references/url-validation.md](references/url-validation.md)
- Preview, pause/resume/stop, traffic limits, retained result filters and exports: [references/runtime-results.md](references/runtime-results.md)

Read [references/common.md](references/common.md) before the first run in a
session. Read [references/evidence.md](references/evidence.md) when reviewing
results.

## Operating workflow

Examples below and in the references run from this skill directory. From a
separate workspace, invoke its absolute `scripts/bypassfuzzer.py` path; the helper
can find the owning checkout’s built CLI. Evidence paths follow the working directory.

1. Apply the session’s established authorized destinations, identities, test data,
   exclusions and operational limits. Resolve only missing constraints needed for
   this run; imported inputs do not expand scope.
2. Use a captured request and real test credentials where the mode needs them.
   Do not invent tokens, accounts, object identifiers, or attacker-controlled
   hosts.
3. Verify the installed CLI:

   ```bash
   python3 scripts/bypassfuzzer.py doctor
   ```

4. Select a new evidence directory that has never been used by another run.
   BypassFuzzer stores full raw messages by default; add `--redact` only when
   the operator wants stored credential headers masked.
5. Run the selected mode through the helper. It preserves BypassFuzzer's native
   options, defaults, output, and exit status:

   ```bash
   python3 scripts/bypassfuzzer.py run bypass \
     --request blocked.raw \
     --target-origin https://app.example \
     --output evidence/bypass-001
   ```

6. Read `summary.json`, then triage candidate records:

   ```bash
   python3 scripts/bypassfuzzer.py triage evidence/bypass-001
   ```

7. Open only the referenced request and response pairs needed to validate a
   candidate. Compare them with the relevant baseline and reproduce the least
   harmful unauthorized capability before calling it a finding.

## Non-obvious boundaries

- `--target-origin` is the socket and TLS destination. Mutated request targets
  and `Host` headers do not reroute the scanner.
- Omitting `--families` in Bypass runs all twelve families. This includes the
  `verb` family and its unusual or state-changing methods.
- Sweep excludes imported `POST`, `PUT`, `PATCH`, and `DELETE` operations unless
  `--include-state-changing` is supplied.
- The CLI never follows redirects. `--oob-domain` or `--oob-generator` supplies
  callback payloads for the shared inventory; the CLI does not own a native Burp
  client or poll interactions. See the URL Validation reference.
- A `LIKELY_BYPASS`, `RESPONSE_CHANGED`, `200`, or parser error is a lead. It is
  not proof of unauthorized access, SSRF, or impact by itself.
- CLI exit code `2` means preflight or usage failure. After a scan starts the
  process returns `0`; inspect `summary.json` for the final state and errors.

## Tool location

`scripts/bypassfuzzer.py` resolves the CLI from `BYPASSFUZZER_CLI`, a
`bypassfuzzer` command on `PATH`, or a source-built JAR near the working directory or the skill’s owning checkout. It requires a
compatible numeric version at least `1.4.4` (including development suffixes) and all five command surfaces
plus the current playbook/calibration, OpenAPI, IDOR, OOB and result-filter options. The
skill does not download or bundle BypassFuzzer.
