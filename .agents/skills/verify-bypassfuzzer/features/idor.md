# IDOR / BOLA analysis

IDOR compares an authorized identifier with a target identifier, establishes control and denied baselines, then runs context-aware path, query, body, and hybrid object-mutation playbooks.

## Sub-features

- `idor-route` sends a selected request through `Send to BypassFuzzer` -> `IDOR`.
- `idor-identifiers` configures `Identifier 1 (authorized)` and `Identifier 2 (target)` as exact literals across the request.
- `idor-baselines` sends the original authorized control and target-identifier unauthorized baseline before playbooks.
- `idor-playbooks` runs registered path, query, body, and hybrid playbooks appropriate to discovered identifier locations.
- `idor-options` uses the shared request-header and throttle controls, including User-Agent variation, global/per-host concurrency, posture, and fixed/smart pause behavior.
- `idor-diagnostics` opens `Playbooks` and `Debug Info`, then copies or saves diagnostics.
- `idor-results` pauses/resumes, stops, clears, filters, inspects results/baselines, and opens the shared `Retry queue (n)` viewer.

## How to get to it (user POV)

- Select a Burp request containing an identifier and choose `Send to BypassFuzzer` -> `IDOR`.
- Choose top-level `IDOR`, then its nested `<METHOD> <path>` session.
- Choose `Configure Attack`; fill `Identifier 1 (authorized)` and `Identifier 2 (target)` and choose `Start IDOR Analysis`.
- Use `Playbooks` for the current registry summary and `Debug Info` -> `Copy to Clipboard` or `Save to File` for mutation diagnostics.
- Use `Pause`, `Stop`, `Clear Results`, filters, result viewers, and the retry control in the shared workspace.

## Driving it with verify-bypassfuzzer

Preconditions:

- The launch and doctor commands passed for the current `RUN_ID`.
- The original request contains identifier 1 in at least one path, query, or JSON-body location.
- Identifier 1 is authorized and identifier 2 is a deliberately selected target for an authorized test account and scope.

- **Automated control/engine proof.** Run `./.agents/skills/verify-bypassfuzzer/helpers/verify.sh drive "$RUN_ID" idor`. The harness proves the context-menu child, mode-specific `Configure Attack`/`Debug Info` surface, per-mode headers, baseline ordering, registered playbook execution, and representative mutation behavior.
- **Configure.** Choose `Configure Attack`, enter both identifiers, and confirm the note `Identifiers are replaced as exact literals across the request.` Review options before choosing `Start IDOR Analysis`.
- **Review shared execution settings.** The IDOR dialog exposes the same `Request Headers...` User-Agent randomizer and complete `Throttle...` dialog used by Bypass, Sweep, and URL Validation.
- **Confirm baselines.** In results, identify the original authorized control and identifier-2 unauthorized baseline before interpreting any playbook result. Capture their request/response viewers.
- **Inspect a mutation.** Select a result from a playbook applicable to the identifier location. Require the request to show identifier 2 plus the named mutation and compare its status/body/length with both baselines.
- **Inspect diagnostics.** Choose `Debug Info`; verify it identifies both values and discovered locations. If testing save, choose `Save to File`, then read the saved file back and retain it with evidence.
- **Proof.** Retain the automated transcript/XML, baseline viewer screenshots, one named mutation's viewers, and any saved debug file/hash.

## Gotchas

- The identifiers are exact literal replacements. Whitespace, encoding, case, or a value absent from the request changes discovery and playbook applicability.
- A target response resembling the control is evidence to review, not an automatic authorization verdict.
- Path, query, body, and hybrid playbooks are context-aware; do not require an inapplicable family to emit variants.
- Debug Info can expose sensitive request data. Store it only in the named local evidence directory and do not paste it into public logs.
- Baselines must run first. A playbook result without both baseline comparisons is incomplete proof.
