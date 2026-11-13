# Targeted authorization bypass

Bypass opens one selected Burp request as a closeable session, runs chosen authorization-bypass attack families, and presents filterable request/response results.

## Sub-features

- `bypass-empty-state` shows `Right-click any request and choose` and `Send to BypassFuzzer → Bypass` when no sessions exist; hides after routing a request and returns after the last confirmed session close.

- `bypass-route` sends the selected Proxy, Sitemap, or Repeater request through `Send to BypassFuzzer` -> `Bypass`.
- `bypass-tab-name` renames a request session from its tab header by double-click or `Rename tab...` in the right-click menu.
- `bypass-selection` enables individual attack families or uses `Check All`/`Uncheck All`.
- `bypass-config` uses `Hide config` / `Show config` in the action row to give results and message viewers more room; toggling preserves selections, scan behavior settings and recorded exchanges. The toggle remains usable during a run.
- `bypass-preview` opens a sortable table of up to 1,000 planned requests and displays the selected request in a Burp message editor.
- `bypass-options` uses the shared execution controls to configure fixed headers, per-request User-Agent variation, hard global/per-host concurrency caps, throttle response codes, posture, and fixed/smart pause behavior through `Options...`.
- `bypass-run` starts, pauses/resumes, stops, clears, and reports planned payloads, actual HTTP sends, recorded results, and deferred retries separately.
- `bypass-filter` applies Smart Filter and manual filters for status, length, content type, host, payload, signal, response content, and highlight.
- `bypass-results` receives bounded UI batches, retains every throttle attempt and raw request/response evidence in Burp's temp-file-backed messages, labels automatic retry attempts, sorts and inspects results, highlights rows, copies TSV, and keeps exhausted/capacity-rejected requests in the shared `Retry queue (n)` viewer.

## How to get to it (user POV)

- In Burp Proxy, Sitemap, or Repeater, select a request and choose `Send to BypassFuzzer` -> `Bypass`.
- Choose top-level `Bypass`, then the nested tab titled `<METHOD> <path>`.
- Double-click the nested tab name or right-click it and choose `Rename tab...`; the renamed title stays with that session.
- Use `Hide config` / `Show config`, the inline attack-family checkboxes, `Check All`, `Uncheck All`, `Options...`, `Preview Requests`, `Start Fuzzing`, `Pause`, `Stop`, `Clear Results`, or the shared `Retry queue (n)` button in the primary action bar.
- Use `Filters`/`Hide filters`, `Smart filter`, `Enable Manual Filter`, and `Apply Manual Filters` beside the results table.
- Select a result to inspect its `Request` and `Response`; use the table context menu for highlights or `Copy selected rows (TSV)`.

## Driving it with verify-bypassfuzzer

Preconditions:

- The launch and doctor commands passed for the current `RUN_ID`.
- Live automated traffic is restricted to the repository's loopback vulnerable lab.
- A manual Burp pass begins with the authenticated blocked request documented for `/edge/private/reports/quarterly`.

- **Full automated proof.** Run `./.agents/skills/verify-bypassfuzzer/helpers/verify.sh drive "$RUN_ID" bypass`. The first layer clicks each `Send to BypassFuzzer` child and verifies nested mode routing. The second requires the Bypass controls and proves a `429` plus three automatic retry attempts remain visible, numbered, and deferred after exhaustion without overflowing silently. The third runs the production Header attack against an isolated lab and requires the `trusted X-Forwarded-For` bypass marker. A black-box lab transcript records baseline and mutated outcomes.
- **Open the session manually.** Send `GET /edge/private/reports/quarterly` with `Cookie: session=lab-user` to `Bypass`. The selected top-level mode is `Bypass`, the nested title starts `GET /edge/private/reports/quarterly`, and the status identifies the same target.
- **Empty state.** Select the mode before sending a request and read its matching context-menu route. Send two requests: the guidance hides. Close one session: it stays hidden. Confirm closing the last session: the guidance returns.
- **Rename the session.** Double-click its nested tab name, enter `Quarterly report`, and require the visible title to change. Right-click the name to find `Rename tab...`; cancelling or entering only spaces must keep the current title.
- **Choose scope.** Use `Uncheck All`, select `Header`, and review `Options...`. Keep Collaborator off unless Professional Collaborator is configured and explicitly in scope.
- **Reclaim workspace.** Choose `Hide config`: the attack-family area disappears and both the table and native editors grow. `Show config` restores the same choices. Open `Playbooks…` to edit Scan behavior; set a custom API prefix and calibration choice, close it, toggle config, then reopen and confirm both settings remain. During an owned run, verify the toggle still works and records stay available.
- **Preview.** Choose `Preview Requests`, sort or select a payload row, and require the Burp request editor below the table to display that row's planned request.
- **Review shared execution settings.** `Request Headers...` includes the same synthetic/browser-like User-Agent randomizer as Sweep. `Throttle...` includes hard global and per-host in-flight caps, throttle codes, posture, and fixed/smart run-wide pause choices.
- **Run and inspect.** Choose `Start Fuzzing`. Require at least one result whose request contains a trusted proxy header and whose response is `200` with `X-Smoke-Bypass: trusted X-Forwarded-For`; select the row and capture both Request and Response viewers.
- **Every family and protocol.** In a disposable project, enable all twelve families / eighteen playbooks, configure a custom User-Agent and Global / Per-host concurrency 20/20, and complete an uncapped run against an owned protocol-aware HTTPS fixture. Require all families and playbook IDs in retained evidence, configured UA values on header-supporting formats, the headerless HTTP/0.9 probe, and raw responses for every request. Preview remains explicitly capped at 1,000; it is not proof of complete execution.
- **Calibration display.** Controls are hidden by default. Once they arrive, Show calibration requests appears beside Filters and the results count identifies hidden calibration rows. Toggle while running and after completion; require the total/evidence/retry counts to stay fixed and normal baselines to remain visible. With Smart filter enabled, controls must not consume candidate repeat slots and must be inspectable when explicitly shown. Select a fallback candidate and keep its Fallback control viewer available with standalone calibration rows hidden.
- **Empty 404 and protocol diagnosis.** A received 404 with Content-Length: 0 and no Content-Type remains 404 in the table. Compare AUTO / HTTP/1 / HTTP/2 against dual-protocol and HTTP/1-only loopback fixtures. A forced HTTP/2 failure is a separate exchange from an HTTP/1 replay returning 404; control labels name their requested protocol. Retain both the raw response and the table state.
- **Pause and filter.** During a sufficiently large run, choose `Pause`, verify the control changes to `Resume`, then resume. Enable a manual `Show only` status filter for `200`, apply it, and ensure the known result remains while nonmatching rows hide without being deleted.
- **Proof.** Retain `user-path.log`, `live-engine.log`, `live-lab-black-box.log`, copied XML, and manual screenshots when a Burp-visible surface changed.

- **Sorting.** Follow the shared results-sorting recipe in [the map index](README.md#driving-conventions), including quick repeated Status clicks with Smart filter on, incoming rows and moved columns.

## Gotchas

- Results use a `Probe` tab with Request and Response side by side. The shared manual filter drawer starts closed; open `Filters` before changing manual filters. The extension theme leaves native Burp editor internals and other tools unchanged.

- `Send to BypassFuzzer` is absent when the context has no selected request.
- `Pause` prevents new sends but does not suppress responses already in flight.
- User-Agent randomization replaces fixed User-Agent values while preserving an intentional additional User-Agent attack value. It is off by default.
- Smart/manual filters change visibility, not the underlying result count. Clear filters before claiming rows are missing.
- The `#` column identifies recorded result rows. Compare the session's HTTP-send telemetry with Burp Logger; `429`/`503` attempts and their labeled retries must now appear in the table even when they remain deferred.
- Collaborator is a production boundary and requires Burp Professional. Do not mock it as proof of an out-of-band interaction.
- A successful status alone is insufficient. Inspect the mutated request and response marker/body against the blocked baseline.
- Closing the nested tab prompts for confirmation and disposes the session; use a disposable run before testing close.

Shared checks also have a [playbook/calibration recipe](playbooks.md). Bypass exposes Playbooks… with family shortcuts and a selected-playbook count. Its pinned Scan behavior section groups default-on Wildcard calibration with a labeled Additional API prefixes field and format hint. Candidate warnings preserve the original signal and retain a selectable Fallback control exchange.

For runtime scope, throttle, playbook and header changes, follow [Pause, edit and resume](editing.md). Initial setup controls remain separate from the active revision.
