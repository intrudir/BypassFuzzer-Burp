# Coverage Sweep

Sweep provides broad, bounded authorization-bypass coverage from in-scope Proxy history, authenticated traffic, imported URL lists, OpenAPI/Swagger documents, Postman collections, or exact retry packages.

## Sub-features

- `sweep-blocked-history` loads in-scope `401`/`403` responses by default, with optional `3xx` and `4xx` groups.
- `sweep-authenticated-history` finds credential-bearing `2xx` traffic, strips selected credentials, and optionally verifies anonymous access.
- `sweep-import` imports text targets, OpenAPI/Swagger, Postman, and retry JSON with optional endpoint dedupe and OpenAPI base URL override.
- `sweep-candidates` reviews, sorts, selects, views, and excludes deduped candidate rows.
- `sweep-probe-preview` chooses `High Signal` or `All Bypass Payloads`, filters families, and displays exact requests before sending.
- `sweep-user-agent` uses the same shared request-header control as every session mode to vary each generated request's User-Agent using synthetic tokens or browser-like variants.
- `sweep-execution` starts, pauses/resumes, stops, clears, and applies adaptive or global throttle controls.
- `sweep-results` inspects request/response evidence, filters it, and uses the shared `Retry queue (n)` viewer; Sweep adds exact retry-package JSON export to that shared dialog.

## How to get to it (user POV)

- Choose `BypassFuzzer` -> `Sweep`; it exists immediately after the extension loads.
- Select mode `Blocked responses`, `Authenticated traffic`, or `Import targets`.
- In history modes, choose `Load from Proxy History` or `Load Authenticated History`.
- In import mode, choose `Import...` -> `Import file` or `Import API specification`; use `Clear Import` to reset.
- Select a candidate and choose `View`, `Preview Probes`, `Exclude...`, or toggle its enabled checkbox.
- Use `Request Headers...` -> `Randomize User-Agent for every request` to select `Synthetic tokens (recommended)` or `Browser-like variants`.
- Use `Payload Families...`, `Throttle...`, `Browser User-Agent`, `Include state-changing methods`, `Start Sweep`, `Pause`, `Stop`, `Clear Results`, the inline shared `Retry queue (n)`, or `Export...`.

## Driving it with verify-bypassfuzzer

Preconditions:

- The launch and doctor commands passed for the current `RUN_ID`.
- Proxy-history checks require a disposable Burp project with known in-scope requests and responses.
- Imported live targets must be loopback lab URLs unless the user explicitly authorizes them.

- **Automated map proof.** Run `./.agents/skills/verify-bypassfuzzer/helpers/verify.sh drive "$RUN_ID" sweep`. The harness changes among all three modes, loads Proxy-history candidates, imports a temporary target list, renders exact generated probes, exercises Start/Stop state, and requires a production-engine likely-bypass classification.
- **Blocked history.** Select `Blocked responses`, keep `401` and `403`, choose `Load from Proxy History`, and wait for `Found <n> ...` rather than sleeping. The preview table contains only matching in-scope responses after dedupe.
- **Authenticated history.** Select `Authenticated traffic`, open `Auth Identifiers...`, keep or adjust `Authorization`/`Cookie`, and choose `Load Authenticated History`. With `Verify unauthenticated access` selected, results distinguish `LIKELY PUBLIC` from a three-response `BYPASS?` signal.
- **Import and preview.** Select `Import targets`, choose `Import...`, import a known text/OpenAPI/Postman fixture, select one row, then choose `Preview Probes`. The dialog must show concrete request lines/headers and the estimate must match enabled candidates, families, and the probe cap.
- **Backslash path coverage.** In `High Signal`, preview a multi-segment target and require raw `\`, `%5c`, and `%5C` prefix, suffix, and sandwich mutations. The raw suffix of segment 1 for `/docs/index.html` is `/docs\/index.html`; the raw prefix of segment 3 for `/ws/chart-api/docs` is `/ws/chart-api/\docs`.
- **Vary User-Agent.** Open `Request Headers...`, select `Randomize User-Agent for every request`, keep `Synthetic tokens (recommended)`, and accept. The Request Headers button shows `UA synthetic`, `Browser User-Agent` becomes inactive, and exact probe preview shows varied `vexa-... orbit-...` values. Switch to `Browser-like variants` only when the application requires browser-shaped syntax.
- **Run.** Choose `Start Sweep`; status becomes `Coverage sweep in progress...`, rows stream into results, and `Pause`/`Stop` enable. Pause stops new sends but can still receive in-flight responses; Resume continues without losing position.
- **Proof.** Retain the automated transcript/XML. For manual import, retain the source fixture, candidate screenshot, exact-probe preview screenshot, and a result's Request/Response viewers.

## Gotchas

- The mode selector changes which source controls are visible. An import attempted outside `Import targets` is correctly rejected.
- `Include state-changing methods` is off by default. Do not enable it against a target without explicit authorization.
- A `4xx` probe remains visible but intentionally gets no interesting signal.
- Preview and execution are invalid if different candidates, payload sets, families, custom headers, browser User-Agent, or randomized User-Agent style settings were used.
- User-Agent randomization replaces fixed/custom and Browser preset values, but retains an additional User-Agent value when a selected attack payload intentionally targets that header.
- User-Agent variation can change cache, content-negotiation, or bot-defense behavior. Compare against an unrandomized control and do not treat fewer `429` responses as an authorization bypass by itself.
- Pause does not cancel already-sent requests. A pause of at least 30 seconds cold-starts the host's adaptive rate when resumed.
- Imported endpoint dedupe defaults off, unlike Proxy-history shape dedupe. Verify the checkbox state before comparing counts.
