# IDOR / BOLA analysis

IDOR compares an authorized identifier with a target identifier, records both baselines, then runs context-aware path, query, body, and hybrid object-mutation playbooks when the baselines are comparable.

## Sub-features

- `idor-route` sends a selected request through `Send to BypassFuzzer` -> `IDOR`.
- `idor-tab-name` renames a request session from its tab header by double-click or `Rename tab...` in the right-click menu.
- `idor-identifiers` configures `Identifier 1 (authorized)`, `Identifier 2 (target)`, and one exact path, query, form, JSON, plain-text, XML, multipart text-field, header, or cookie location above a read-only native Burp request editor. The editor searches the typed identifier live.
- `idor-coverage` plans every applicable mutation from enabled playbooks without a numeric cap. Configure Attack shows that policy, and Preview Requests shows the planned request count; two baselines and possible retries still apply.
- `idor-baselines` sends the original authorized control and target-identifier unauthorized baseline before playbooks.
- `idor-diagnostics` reports baseline-only stops and scan failures in the session and Burp Extensions `Errors` output; failures include a stack trace.
- `idor-playbooks` runs registered path, query, body, and hybrid playbooks appropriate to discovered identifier locations.
- `idor-response-guided` optionally discovers exact identifier values in baseline JSON and probes derived request-body fields in both authorized-path and target-path directions.
- `idor-options` uses the shared request-header and throttle controls, including User-Agent variation, hard global/per-host concurrency caps, posture, and fixed/smart pause behavior.
- `idor-debug-info` opens `Playbooks` and `Debug Info`, then copies or saves mutation diagnostics.
- `idor-results` pauses/resumes, stops, clears, receives bounded UI batches with temp-file-backed raw evidence, reports physical HTTP sends separately from recorded/shown results, filters and inspects results/baselines, and opens the shared `Retry queue (n)` viewer.

## How to get to it (user POV)

- Select a Burp request containing an identifier and choose `Send to BypassFuzzer` -> `IDOR`.
- Choose top-level `IDOR`, then its nested `<METHOD> <path>` session.
- Double-click the nested tab name or right-click it and choose `Rename tab...` to label the session.
- Choose `Configure Attack`; fill `Identifier 1 (authorized)` and `Identifier 2 (target)` and choose `Start IDOR Analysis`.
- Use `Playbooks` for the current registry summary and `Debug Info` -> `Copy to Clipboard` or `Save to File` for mutation diagnostics.
- Use `Pause`, `Stop`, `Clear Results`, filters, result viewers, and the retry control in the shared workspace.

## Driving it with verify-bypassfuzzer

Preconditions:

- The launch and doctor commands passed for the current `RUN_ID`.
- The original request contains identifier 1 in at least one path, query, or JSON-body location.
- Identifier 1 is authorized and identifier 2 is a deliberately selected target for an authorized test account and scope.

- **Automated control/engine proof.** Run `./.agents/skills/verify-bypassfuzzer/helpers/verify.sh drive "$RUN_ID" idor`. The harness proves the context-menu child, mode-specific `Configure Attack`/`Debug Info` surface, separate HTTP-send/result accounting, per-mode headers, baseline ordering, registered playbook execution, and representative mutation behavior.
- **Configure.** Choose `Configure Attack` and require the original request to be visible below the controls in a Burp message editor. Type identifier 1 and require Burp's search to highlight matching text without leaving the dialog. Click `Find Locations` to populate the exact location dropdown, then select a location; on Burp versions with caret positioning, the editor should scroll to that slot. Choose `Preview Requests`, select a payload row in the table, and require the Burp editor below to display that generated request before choosing `Start IDOR Analysis`.
- **Rename the session.** Double-click its nested tab name, enter `Other user comparison`, and require the visible title to change while the same request session remains selected. Right-click the name to find `Rename tab...`.
- **Switch sessions.** Open two IDOR request tabs. While one scans, click the other tab's title and require that session to become visible; click anywhere else in its header to switch back. The entire header should select the tab without affecting the running scan.
- **Coverage.** For POST and GET, require no mutation-limit control. Preview a path identifier and require every eligible paired separator plus other applicable playbook rows, with both baselines first. The preview reports its complete planned count and notes that live response-guided probes may add requests after baselines.
- **Review shared execution settings.** The IDOR dialog exposes the same `Request Headers...` User-Agent randomizer and complete `Throttle...` dialog used by Bypass, Sweep, and URL Validation. Treat the configured global and per-host concurrency values as hard in-flight upper bounds.
- **Confirm baselines.** In results, identify the original authorized control and identifier-2 unauthorized baseline before interpreting any playbook result. Capture their request/response viewers.
- **Check 2xx target baselines.** If both baselines return HTTP 200 but the target body has diminished permissions, require the target baseline to show `TARGET_BASELINE_2XX_REVIEW` and the selected mutation requests to run. Compare each mutation with the target baseline; a changed body is `RESPONSE_CHANGED`, not proof of access.
- **Check early stops.** When only two baseline requests are sent, inspect the session warning and `Extensions` -> `Installed` -> `BypassFuzzer` -> `Errors`. Failed authorized controls and inconclusive target responses such as redirects still stop ordinary mutations. Transport and scan exceptions appear in `Errors`, with stack traces for exceptions.
- **Confirm accounting.** While running or after completion, require `HTTP request(s) sent` to reflect network attempts independently of `result(s) recorded` and any filtered `showing` count. Retry Queue sends must increase the HTTP total.
- **Inspect a mutation.** Select a result from a playbook applicable to the identifier location. Require the request to show identifier 2 plus the named mutation and compare its status/body/length with both baselines.
- **Response-guided family.** Send a request with a successful JSON response to the IDOR tab. In Configure Attack, enter both identifiers, click `Inspect Response Fields`, and require exact matching response JSON pointers. Confirm `idor.body.response_guided_mass_assignment` is checked by default in `Select Playbooks...`; `Preview Requests` should show both directions and the generated body in the native editor. A response field that echoes the target ID is a candidate for manual readback, not confirmed persistence.
- **Paired controls.** Confirm `idor.hybrid.paired_control_separators` is checked by default. With IDs `7651` and `7648` in a path, the first two mutation previews must show `7651%0A7648` and `7648%0A7651`, each with an LF label. Confirm the preview states planned/eligible separator counts; a selected HTTP/2 header or cookie shows a skip note instead of raw CR/LF probes.
- **Dangerous identifier opt-in.** Confirm numeric pivots, special identifier values, JSON edge cases, canonical formats, and truncated variants are unchecked by default and labeled DANGEROUS. Select one, accept the playbook chooser, then decline the warning: it must remain unchecked. Repeat and accept the warning: preview can now include identifiers beyond the two entered. Turn it off again before testing a scope that excludes those IDs.
- **Inspect diagnostics.** Choose `Debug Info`; verify it identifies both values and discovered locations. If testing save, choose `Save to File`, then read the saved file back and retain it with evidence.
- **Proof.** Retain the automated transcript/XML, baseline viewer screenshots, one named mutation's viewers, and any saved debug file/hash.

## Gotchas

- Discovery requires an exact selectable value. Plain-text occurrences must have identifier boundaries; XML entity-derived values, CDATA, multipart files, and credential-bearing headers/cookies are not selectable.
- A target response resembling the control is evidence to review, not an automatic authorization verdict.
- The response-guided family is checked by default and uses live baselines for execution; a captured response is only a preview source. When no response is attached, pre-scan preview cannot show its dynamic probes.
- Numeric pivots, special values such as `0`, `1`, `-1`, JSON edge cases, canonical formats, and truncated variants are off by default because they can address other users' objects. Enabling any requires a Burp warning confirmation.
- Path, query, body, and hybrid playbooks are context-aware; do not require an inapplicable family to emit variants.
- Debug Info can expose sensitive request data. Store it only in the named local evidence directory and do not paste it into public logs.
- Baselines must run first. A playbook result without both baseline comparisons is incomplete proof.
