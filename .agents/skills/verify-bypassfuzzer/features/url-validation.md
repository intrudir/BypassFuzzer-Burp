# URL Validation

URL Validation edits a selected request around one or more `{INJECT}` markers, previews exact payloads for URL/host/origin contexts, and runs allow-list or SSRF-style parser-mismatch tests.

## Sub-features

- `urlval-route` sends a selected request through `Send to BypassFuzzer` -> `URL Validation`.
- `urlval-workbench` edits the exact request, places `{INJECT}` markers, and resets to the original request.
- `urlval-context` configures Absolute URL, Host header, or CORS contexts plus allowed and attacker-controlled hosts.
- `urlval-families` selects attack settings and encodings, then uses the shared request-header/User-Agent and complete throttle controls.
- `urlval-preview` uses `View Payloads` or `Copy Payloads` to inspect the exact generated set before execution.
- `urlval-run` starts, pauses/resumes, stops, clears, and reports marker/payload progress.
- `urlval-results` inspects request/response pairs, filters rows, and opens the shared `Retry queue (n)` viewer.

## How to get to it (user POV)

- Select a request in Burp and choose `Send to BypassFuzzer` -> `URL Validation`.
- Choose top-level `URL Validation`, then its nested `<METHOD> <path>` session.
- Choose `Configure Attack`; edit the `Request Workbench` to insert `{INJECT}` in a query value, header, or body.
- Select the relevant context/settings and enter the allow-listed host plus attacker host, or enable Burp Collaborator when available and authorized.
- Choose `View Payloads`, `Copy Payloads`, `Start URL Validation`, or `Reset Request`.
- Use `Pause`, `Stop`, `Clear Results`, filters, viewers, and retry controls after the run begins.

## Driving it with verify-bypassfuzzer

Preconditions:

- The launch and doctor commands passed for the current `RUN_ID`.
- The edited request contains at least one literal `{INJECT}` marker or the selected automatic context has a valid candidate.
- An attacker host is configured unless Collaborator is both available and selected.

- **Automated user-path/live proof.** Run `./.agents/skills/verify-bypassfuzzer/helpers/verify.sh drive "$RUN_ID" url-validation`. The harness proves mode routing, mode-specific controls and headers, payload generation, then runs marker mode through the production URL Validation engine against an isolated lab and requires the URL allow-list bypass marker.
- **Set marker.** Send `GET /redirect/next?next={INJECT}` to URL Validation, choose `Configure Attack`, and confirm the Request Workbench still contains the marker in the exact request that will be sent.
- **Configure and preview.** Select the Absolute URL context, enter the trusted and attacker hosts used by the lab recipe, and choose `View Payloads`. Capture at least one generated `trusted@attacker`-style payload and confirm the preview count matches the enabled settings/encodings.
- **Review shared execution settings.** `Request Headers...` includes synthetic/browser-like per-request User-Agent variation. `Throttle...` includes global/per-host concurrency, throttle codes, posture, and fixed/smart run-wide pauses.
- **Run and inspect.** Choose `Start URL Validation`; the dialog hides, status becomes `URL validation fuzzing in progress...`, and results appear. Require a request in which `{INJECT}` was replaced and a response carrying the lab's `url-allowlist-bypass` marker.
- **Reset.** Reopen `Configure Attack`, choose `Reset Request`, and confirm the original request replaces all edits before starting another scenario.
- **Proof.** Retain `user-path.log`, `live-engine.log`, copied XML, preview screenshots, and one result's Request/Response viewers.

## Gotchas

- Starting without an attacker host is rejected unless Collaborator payloads are enabled and available.
- The Request Workbench is the exact active request; editing a separate Repeater copy after routing does not update it.
- `Reset Request` intentionally discards workbench edits, including markers.
- Payload preview is valid only for the same contexts, settings, encodings, hosts, headers, and request used at execution.
- Collaborator verifies an external production boundary and can create real out-of-band traffic. Use it only with explicit scope and preserve interaction evidence separately.
- A final `200` alone is not proof: capture the substituted request and the response marker/body that distinguishes it from the blocked baseline.
