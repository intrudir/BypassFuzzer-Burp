# Targeted authorization bypass

Bypass opens one selected Burp request as a closeable session, runs chosen authorization-bypass attack families, and presents filterable request/response results.

## Sub-features

- `bypass-route` sends the selected Proxy, Sitemap, or Repeater request through `Send to BypassFuzzer` -> `Bypass`.
- `bypass-selection` enables individual attack families or uses `Check All`/`Uncheck All`.
- `bypass-options` uses the shared execution controls to configure fixed headers, per-request User-Agent variation, hard global/per-host concurrency caps, throttle response codes, posture, and fixed/smart pause behavior through `Options...`.
- `bypass-run` starts, pauses/resumes, stops, clears, and reports state for a session.
- `bypass-filter` applies Smart Filter and manual filters for status, length, content type, host, payload, signal, response content, and highlight.
- `bypass-results` receives bounded UI batches, retains raw request/response evidence in Burp's temp-file-backed messages, sorts and inspects results, highlights rows, copies TSV, and opens the shared `Retry queue (n)` viewer for throttled/no-response requests.

## How to get to it (user POV)

- In Burp Proxy, Sitemap, or Repeater, select a request and choose `Send to BypassFuzzer` -> `Bypass`.
- Choose top-level `Bypass`, then the nested tab titled `<METHOD> <path>`.
- Use the inline attack-family checkboxes, `Check All`, `Uncheck All`, `Options...`, `Start Fuzzing`, `Pause`, `Stop`, or `Clear Results`.
- Use `Hide Filters`/`Show Filters`, `Enable (auto-detect patterns)`, `Enable Manual Filter`, and `Apply Manual Filters` beside the results table.
- Select a result to inspect its `Request` and `Response`; use the table context menu for highlights or `Copy selected rows (TSV)`.

## Driving it with verify-bypassfuzzer

Preconditions:

- The launch and doctor commands passed for the current `RUN_ID`.
- Live automated traffic is restricted to the repository's loopback vulnerable lab.
- A manual Burp pass begins with the authenticated blocked request documented for `/edge/private/reports/quarterly`.

- **Full automated proof.** Run `./.agents/skills/verify-bypassfuzzer/helpers/verify.sh drive "$RUN_ID" bypass`. The first layer clicks each `Send to BypassFuzzer` child and verifies nested mode routing. The second requires the Bypass controls. The third runs the production Header attack against an isolated lab and requires the `trusted X-Forwarded-For` bypass marker. A black-box lab transcript records baseline and mutated outcomes.
- **Open the session manually.** Send `GET /edge/private/reports/quarterly` with `Cookie: session=lab-user` to `Bypass`. The selected top-level mode is `Bypass`, the nested title starts `GET /edge/private/reports/quarterly`, and the status identifies the same target.
- **Choose scope.** Use `Uncheck All`, select `Header`, and review `Options...`. Keep Collaborator off unless Professional Collaborator is configured and explicitly in scope.
- **Review shared execution settings.** `Request Headers...` includes the same synthetic/browser-like User-Agent randomizer as Sweep. `Throttle...` includes hard global and per-host in-flight caps, throttle codes, posture, and fixed/smart run-wide pause choices.
- **Run and inspect.** Choose `Start Fuzzing`. Require at least one result whose request contains a trusted proxy header and whose response is `200` with `X-Smoke-Bypass: trusted X-Forwarded-For`; select the row and capture both Request and Response viewers.
- **Pause and filter.** During a sufficiently large run, choose `Pause`, verify the control changes to `Resume`, then resume. Enable a manual `Show only` status filter for `200`, apply it, and ensure the known result remains while nonmatching rows hide without being deleted.
- **Proof.** Retain `user-path.log`, `live-engine.log`, `live-lab-black-box.log`, copied XML, and manual screenshots when a Burp-visible surface changed.

## Gotchas

- `Send to BypassFuzzer` is absent when the context has no selected request.
- `Pause` prevents new sends but does not suppress responses already in flight.
- User-Agent randomization replaces fixed User-Agent values while preserving an intentional additional User-Agent attack value. It is off by default.
- Smart/manual filters change visibility, not the underlying result count. Clear filters before claiming rows are missing.
- Collaborator is a production boundary and requires Burp Professional. Do not mock it as proof of an out-of-band interaction.
- A successful status alone is insufficient. Inspect the mutated request and response marker/body against the blocked baseline.
- Closing the nested tab prompts for confirmation and disposes the session; use a disposable run before testing close.
