# Coverage Sweep

Sweep provides broad authorization-bypass coverage from in-scope Proxy history, authenticated traffic, imported URL lists, OpenAPI/Swagger documents, Postman collections, or exact retry packages. `High signal` uses a bounded corpus; `All payloads` runs the complete catalog for every selected family.

## Sub-features

- `sweep-blocked-history` loads in-scope `401`/`403` responses by default, with optional `3xx` and `4xx` groups.
- `sweep-authenticated-history` finds credential-bearing `2xx` traffic, strips selected credentials, and optionally verifies anonymous access. `Skip likely public endpoints` is selected by default: it retains the `LIKELY PUBLIC` control result, skips further probes for that candidate, and shows the skipped-endpoint count in Sweep status.
- `sweep-import` imports text targets, OpenAPI/Swagger, Postman, and retry JSON with optional endpoint dedupe and OpenAPI base URL override.
- `sweep-openapi-variables` selects an OpenAPI parameter policy and sets managed variables before running requests with unresolved placeholders.
- `sweep-workbench` collapses/reopens the configuration rail, shows loaded candidates, and puts `#`, `Payload`, `Host`, `Family`, `Signal`, `Status`, `Length`, `Content-Type` in the results table.
- `sweep-candidates` reviews, sorts, selects, views, excludes, and optionally dedupes candidate rows by endpoint while ignoring query parameters.
- `sweep-probe-preview` chooses `High signal` or `All payloads`, filters families, and displays exact requests before sending.
- `sweep-user-agent` uses the same shared request-header control as every session mode to vary each generated request's User-Agent using synthetic tokens or browser-like variants.
- `sweep-execution` starts, pauses/resumes, stops, clears, applies hard global/per-host concurrency caps, and lazily plans only active candidates.
- `sweep-failures` reports planner/setup/candidate failures in a selectable `Run errors (n)` dialog, marks the activity Failed, preserves successful candidates, and excludes failed hosts from completed-host exports. The next run clears prior failures.
- `sweep-results` receives bounded UI batches, retains raw probe evidence in Burp's temp-file-backed messages, filters it, and uses the shared `Retry queue (n)` viewer; Sweep adds exact retry-package JSON export to that shared dialog.

## How to get to it (user POV)

- Choose `BypassFuzzer` -> `Sweep`; it exists immediately after the extension loads.
- Select mode `Blocked responses`, `Authenticated traffic`, or `Import targets`.
- In history modes, choose `Load from Proxy History` or `Load Authenticated History`.
- In import mode, choose `Import...` -> `Import file` or `Import API specification`.
- Keep `Dedupe on endpoint` selected to retain one request per scheme, host, port, method, and normalized path while ignoring cache-busting and other query parameters; clear it to retain every matching request.
- In any mode, use `Clear Candidates` in the `Source` configuration group to remove the currently loaded candidate set without changing modes.
- Select a candidate and choose `View`, `Preview Probes`, `Exclude...`, or toggle its enabled checkbox.
- Use `Request Headers...` -> `Randomize User-Agent for every request` to select `Synthetic tokens (recommended)` or `Browser-like variants`.
- Use `Payload Families...`, `Throttle...`, `Browser User-Agent`, `State-changing methods`, `Start Sweep`, `Pause`, `Stop`, `Clear Results`, the inline shared `Retry queue (n)`, or `Export...`.

## Driving it with verify-bypassfuzzer

Preconditions:

- The launch and doctor commands passed for the current `RUN_ID`.
- Proxy-history checks require a disposable Burp project with known in-scope requests and responses.
- Imported live targets must be loopback lab URLs unless the user explicitly authorizes them.

- **Automated map proof.** Run `./.agents/skills/verify-bypassfuzzer/helpers/verify.sh drive "$RUN_ID" sweep`. The harness changes among all three modes, loads Proxy-history candidates, imports a temporary target list, renders exact generated probes, exercises Start/Stop state, and requires a production-engine likely-bypass classification. It also proves that `All payloads` completes the generated catalog, configured concurrency is an exact upper bound, candidate plans are created lazily, Swing delivery is bounded and batched, and raw evidence is copied to temp-file-backed messages.
- **Blocked history.** Select `Blocked responses`, keep `401` and `403`, choose `Load from Proxy History`, and wait for `Found <n> ...` rather than sleeping. The preview table contains only matching in-scope responses after dedupe. The `Source` group contains `Pull responses` and its status checkboxes only in blocked mode; `Dedupe on endpoint` is in `Probes`.
- **Authenticated history.** Select `Authenticated traffic`, open `Auth Identifiers...`, keep or adjust `Authorization`/`Cookie`, and choose `Load Authenticated History`. With `Verify unauthenticated access` selected, results distinguish `LIKELY PUBLIC` from a three-response `BYPASS?` signal. `Skip likely public endpoints` starts selected and is enabled only while verification is selected. A public control result remains visible, but no mutation probes run for that candidate; running and completed status show `N public endpoints skipped`. Clear the checkbox to probe those candidates too.
- **Import and preview.** Select `Import targets`, choose `Import...`, import a known text/OpenAPI/Postman fixture, select one row, then choose `Preview Probes`. Select a probe row in the preview table and require the Burp editor below to show its concrete request lines and headers. The estimate must match enabled candidates, families, and the probe cap.
- **API parameters.** Import a spec with a missing required path/query value. In `Import options`, select a parameter policy and choose `Manage Variables...`. The default required-variable policy leaves explicit placeholders; set every required value before running. Rebuild with the base URL override and inspect the concrete request in preview.
- **Results workspace.** Use `Smart filter` in the results toolbar; choose `Filters` to open the manual drawer and `Hide filters` to close it. Select a probe to inspect Request and Response side by side in `Probe`, or the baseline pair in `Original`; authenticated history can add `Auth verification`. `Export...` and `Clear Results` are in the results toolbar. An empty candidate table is collapsed automatically.
- **Native layout.** Switch among all three source modes at 1700×1100 and 1280×900. The configuration column must track its viewport width; Import targets must not widen or clip the source, probes, execution or OpenAPI controls. Scroll to Import options and check every compact parameter-policy label fits while retaining the same enum value. Open Sweep after Burp initially selected another tab, then import candidates. Require visible result rows and readable native Request/Response bodies without first dragging a divider. Open `Throttle...` and confirm its Close button stays visible while settings scroll.
- **Clear candidates.** After loading rows in each mode, choose `Clear Candidates`. The candidate table becomes empty, Start/View/Preview become unavailable, and the current mode remains selected.
- **Dedupe on endpoint.** In each mode, keep `Dedupe on endpoint` selected and load two requests whose scheme, host, port, method, and normalized path match but whose query parameter names and values differ. Only the newest history request, or first imported request, remains. Clear the checkbox and reload to retain both.
- **Backslash path coverage.** With `High signal` selected, preview a multi-segment target and require raw `\`, `%5c`, and `%5C` prefix, suffix, and sandwich mutations. The raw suffix of segment 1 for `/docs/index.html` is `/docs\/index.html`; the raw prefix of segment 3 for `/ws/chart-api/docs` is `/ws/chart-api/\docs`.
- **Vary User-Agent.** Open `Request Headers...`, select `Randomize User-Agent for every request`, keep `Synthetic tokens (recommended)`, and accept. The Request Headers button shows `UA synthetic`, `Browser User-Agent` becomes inactive, and exact probe preview shows varied `vexa-... orbit-...` values. Switch to `Browser-like variants` only when the application requires browser-shaped syntax.
- **All payloads with a User-Agent.** Import an owned URL-list file, choose All payloads, set `User-Agent: Sweep-Repro-UA` in Request Headers, and set Global concurrency / Per-host to 20/20. Require the full Preview Probes inventory to open without traffic, then run the same selection to completion. Keep Protocol enabled: the HTTP/0.9 request must remain a versionless line with no headers, while HTTP/1.0, HTTP/1.1 and HTTP/2 retain the configured UA. Test fixed and both randomized-UA styles through the shared header-policy regressions. A native Montoya request reports a null version for HTTP/0.9; never substitute the High signal inventory for this case. Retain the result requests/responses and the owned fixture's received request line/header counts.
- **Run.** Choose `Start Sweep`; status becomes `Coverage sweep in progress...`, rows stream into results, and `Pause`/`Stop` enable. Pause stops new sends but can still receive in-flight responses; Resume continues without losing position. `All payloads` completes the entire selected catalog unless stopped; only active workers hold candidate probe plans, and the configured concurrency values are hard upper bounds.
- **Failure visibility.** Use the engine regression fixture to throw a planner/API linkage error for one candidate. Require a Failed activity and `Run errors (n)` with the request and exception; the other candidate must execute, the failed host must stay out of completed hosts, and a subsequent clean run must clear failures. Keep the first 100 messages; full error logs remain in Extensions. An invalid API prefix must show a validation message before traffic without disabling Import or Start. Fixing it must refresh the estimate. A text URL list alone is a supported input and must complete against an owned loopback fixture with completed/planned counts equal.
- **Proof.** Retain the automated transcript/XML. For manual import, retain the source fixture, candidate screenshot, exact-probe preview screenshot, and a result's Request/Response viewers.

## Gotchas

- The mode selector changes which source controls are visible. An import attempted outside `Import targets` is correctly rejected.
- `State-changing methods` is off by default. Do not enable it against a target without explicit authorization.
- A `4xx` probe remains visible but intentionally gets no interesting signal.
- Preview and execution are invalid if different candidates, payload sets, families, custom headers, browser User-Agent, or randomized User-Agent style settings were used.
- User-Agent randomization replaces fixed/custom and Browser preset values, but retains an additional User-Agent value when a selected attack payload intentionally targets that header.
- User-Agent variation can change cache, content-negotiation, or bot-defense behavior. Compare against an unrandomized control and do not treat fewer `429` responses as an authorization bypass by itself.
- Pause does not cancel already-sent requests. A pause of at least 30 seconds cold-starts the host's adaptive rate when resumed.
- Endpoint dedupe defaults on in every mode and intentionally ignores the complete query string. Clear it when distinct query variants must each be tested.

The [shared playbook/calibration recipe](playbooks.md) covers both inventories. High signal includes a Verb group; post/put requires State-changing methods, now exposed in every Sweep source mode. Selections remain independent per inventory. Authenticated calibration and mutations use the same stripped credential context. Fallback controls cannot replace Original or Auth verification evidence. Column order stays Payload, Host, Family, Signal, Status, Length, Content-Type.
