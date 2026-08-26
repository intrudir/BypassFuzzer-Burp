# Coverage Sweep Mode

The `Sweep` tab is the broad coverage mode for BypassFuzzer.

It is designed for the case where an assessment has many blocked endpoints in Burp Proxy history, or a curated text file of target URLs, and the tester wants a bounded, high-signal check across them. It is not a full scanner and it does not run the full Bypass playbooks against every endpoint.

## When To Use It

Use Sweep when:

- Proxy history contains in-scope `401` or `403` responses
- you have a `.txt` file with one absolute target URL per line
- you want a quick coverage pass across many blocked endpoints
- you want to check common path-normalization and lightweight header cases without sending thousands of requests per endpoint

Use a targeted request tab instead when:

- one endpoint deserves deeper testing
- you want the full AuthZ bypass playbooks
- you want IDOR/BOLA mutation against a known object identifier
- you need URL validation payload generation with `{INJECT}` markers

## Startup Behavior

Sweep is available immediately when the extension loads.

The top-level extension tabs are:

- `Dashboard`
- `Sweep`
- `Bypass`
- `IDOR`
- `URL Validation`

Requests sent to a targeted mode appear as closeable tabs beneath that mode.

The Dashboard lists Sweep and every open targeted request session. It provides global and per-row
Pause/Resume/Stop controls plus optional extension-wide limits. Hard limits start disabled on each
Burp launch; the initial values are 10 requests/second per host and 10 total in-flight requests.
They apply to primary scans and automatic/manual retry traffic across every mode.

## Candidate Collection

Sweep loads candidates from Burp Proxy history or an imported target list.

Sweep has three source modes:

- `Blocked responses` loads the configured blocked/error status codes and compares probes with a live control request.
- `Authenticated traffic` passively loads in-scope `2xx` history, identifies requests using user-selected auth header or cookie names, strips authentication, and sends only mutated probes.
- `Import targets` shows the import control and loads a `.txt` file containing one absolute URL per line.

The Proxy-history load control is shown only for the two history modes. `Import Targets` is shown only in import mode. Response-status filters are shown only in `Blocked responses`.
Proxy-history discovery runs in the background so large authenticated history sets do not block Burp's interface.
When automatic HTTP negotiation returns no response, Sweep retries safe `GET` and `HEAD` probes over HTTP/1. Remaining transport failures stay visible as `No response` rows and are written to the extension error log with the affected method and URL.

By default it selects:

- `401`
- `403`

The UI also allows opt-in loading of:

- `3xx`
- `4xx`

Only in-scope Proxy history items are loaded.

Imported target files use one absolute URL per line:

```text
https://victim.com/admin/users
https://victim.com/admin/info
```

Blank lines, comment lines beginning with `#`, and invalid URLs are ignored. Imported targets are deduplicated and shown in the preview table before Sweep sends any requests. `View` opens the selected request and response side by side in a resizable window. The response side remains empty for imported URLs until the Control request runs because a URL list contains no stored response.
Imported targets are unavailable in authenticated-traffic mode because they have no stored authenticated request or response.

Import mode also accepts OpenAPI 3 and Swagger 2 specifications in JSON or YAML. Each documented operation becomes a candidate using its HTTP method and server/path combination. Documented path, query, header, cookie, form, and body parameters are retained, including reusable local parameter references and operation-level overrides. Examples/defaults are preferred; missing values receive type-appropriate samples so the parameter remains in the candidate request. Query arrays and objects follow their declared OpenAPI style/explode settings. Request bodies are generated from media-type examples or schemas.

For URL imports, relative document links and redirects preserve unusual raw paths such as repeated slashes and backslashes. Relative servers—and OpenAPI's implicit `/` when no server is declared—resolve against the final document URL. An optional `OpenAPI base URL` overrides the resolved specification server.

## Authenticated Traffic

Authenticated-traffic discovery does not send requests. It inspects Proxy history and inventories likely authentication header names and cookie names without displaying their values. `Authorization` and session/auth/token-like identifiers are selected automatically; the tester can change the selection and add custom auth header names.

A `2xx` history request is included when it contains at least one selected identifier. `GET` and `HEAD` are included by default. State-changing methods require the explicit `Include state-changing methods` option.

Images, JavaScript, CSS, and WOFF/WOFF2 responses are excluded by default using their response `Content-Type` or request-path extension. Clear `Exclude static assets` before loading authenticated history when those resources should be included.

Cookie selections are identifiers only. Before attacks are generated, Sweep removes:

- the entire `Cookie` header
- `Authorization`
- `Proxy-Authorization`
- additional auth headers selected by the tester

When `Verify unauthenticated access` is enabled, Sweep first replays the original request with authentication removed. A successful compatible `2xx` response is shown as `LIKELY PUBLIC: authenticated X -> unauthenticated Y`. This is a review signal, not confirmation: stale sessions, public endpoints, incomplete auth-identifier selection, and generic `200` responses can all produce false positives. The anonymous control response is retained in the result viewer alongside the original authenticated exchange. Authenticated Sweep results also provide dedicated `Auth Verification Request` and `Auth Verification Response` tabs for reviewing the exact credential-stripped exchange used for classification.

If the anonymous control is blocked and a mutation succeeds, Sweep labels that result `LIKELY UNAUTHENTICATED BYPASS: X -> Y`. This is distinct from `LIKELY PUBLIC`: it means the endpoint was not directly reachable without credentials, but a crafted request changed the anonymous response.

When the authenticated history response is successful, the anonymous control is a `3xx` or `4xx`, and a credential-stripped mutation returns `2xx`, Sweep emits the stronger three-response signal:

```text
BYPASS?: authenticated 200 -> anonymous 403 -> probe 200
```

`401`, `403`, and redirects are treated as strong authentication boundaries. Other `4xx` responses are marked `BYPASS? (weak)` because they may represent routing or application errors rather than authorization.

Verification is enabled by default for authenticated traffic. State-changing methods still require `Include state-changing methods`.

The shared Manual Filter includes `Signal contains` with optional regex support. Use `BYPASS?` to focus on these candidates, `LIKELY PUBLIC` to focus on direct anonymous access, or an exact transition such as `anonymous 403 -> probe 200`.

## Deduplication

Sweep deduplicates candidates before previewing or sending probes.

The dedupe key includes:

- scheme, host, and port
- HTTP method
- normalized path shape
- sorted query parameter names
- request `Content-Type`

When multiple history items match the same dedupe key, Sweep keeps the most recent request.

## Execution Controls

Sweep runs one candidate sequentially, but can run multiple candidates concurrently across every
host at once.

### Adaptive rate control

Pacing is fully automatic and **per host**. Each host key (`scheme://host:port`) gets its own
adaptive controller that discovers that host's rate-limit ceiling and rides just under it:

- It ramps up quickly until the first throttle reveals the ceiling, then holds the rate just below it
  — backing off gently on each throttle and probing upward again — so throughput stays high while
  throttles stay rare (typically well under 2% once converged).
- `Retry-After` is honored as a hard pause.
- A throttled probe is automatically re-queued and retried, so a brief block never drops coverage.
- Because adaptive limits are tracked per host, imported hosts can be swept in parallel. When the
  Dashboard hard limiter is enabled, all sessions targeting the same host also share its configured
  smooth requests/second ceiling, while every host shares the Dashboard total in-flight cap.

The `Throttle...` dialog also offers a Sweep-wide CDN/WAF cooldown layered on top of the per-host
controllers:

- `No global pause (adaptive)` keeps the original independent per-host behavior. It does not add a
  Sweep-wide cooldown, although a server-provided `Retry-After` still pauses the affected host.
- `Fixed pause` stops new requests to every Sweep host after any configured throttle response for
  the chosen number of seconds.
- `Smart Pause` tolerates isolated throttle responses. It pauses one saturated host after either
  eight consecutive throttles or a rolling window of at least 25 responses where at least 10 and
  40% are throttled. The same ratio or streak pauses the entire Sweep only when throttle responses
  span multiple hosts, which identifies a likely shared CDN/WAF limit. Cooldowns escalate through
  10, 20, 40, 80, and 120 seconds. After a cooldown, the circuit sends one recovery request at a
  time and requires five successes before reopening normal flow; another throttle extends the
  cooldown. After a quiet minute, escalation resets. A server-provided `Retry-After` value is always
  used when it requires a longer cooldown.

`Concurrency` and `Per-host` bound how many requests may be *in flight* at once (a resource cap), not
the rate. `Throttle codes` defaults to `429,503` and defines which responses count as a rate-limit
signal.

Manual `Pause` freezes both network sending and throttle admission. Already-sent requests may still
finish and appear in the results table. Resume discards token-bucket credit accumulated during the
pause and releases only one initial request per host. Pauses of 30 seconds or longer also cold-start
each host at the safe initial adaptive rate, while preserving the current Sweep position and retry
queue.

### Browser User-Agent

The `Browser User-Agent` preset (on by default) sends every probe with a current desktop Chrome
`User-Agent`. If you set your own `User-Agent` in `Request Headers`, that value is used instead.

The shared `Request Headers...` control used by Bypass, Sweep, IDOR, and URL Validation also offers
`Randomize User-Agent for every request`. It is off by default.
When enabled, it overrides both the Browser preset and any fixed `User-Agent` line while leaving
other configured headers unchanged. `Synthetic tokens (recommended)` generates valid, deliberately
non-browser product tokens such as `vexa-... orbit-...`; `Browser-like variants` generates varied
Chrome-, Firefox-, and Safari-shaped strings for applications that require browser syntax.

Each distinct generated request receives a stable value for that Sweep run, so `Preview Probes`
continues to show the exact initial request. Intentional User-Agent attack payloads remain as an
additional header value. Treat UA variation as a transport/fingerprinting option: compare it with an
unrandomized control, because it can also change cache, bot-defense, and content-negotiation behavior.

### Payload families

`Payload Families...` controls which technique categories Sweep may send. The dialog keeps separate
selections for the two payload inventories:

- `High Signal` lists the curated Sweep categories such as Header, Path Normalization, Encoding,
  Debug Params, and Content-Type.
- `All Bypass Families` lists the complete Bypass attack families such as Header, Path, Verb,
  Debug Cookies, Protocol, and Case Variation.

The High Signal `Host Parsing` family includes double-port Host probes by default
(`host:port:80` and `host:port:443`). Its enable switch and optional custom-port field are located
inside `Payload Families...`; custom ports add `host:custom`, `host:custom:80`, and
`host:custom:443` variants.

All families are enabled by default. Clear an individual family, such as `Header`, or use
`Uncheck All` and select only the families needed for the current assessment. Switching the payload
set does not discard either tab's selections. Disabled families are removed before the probe budget
and request deduplication are applied.

## Probe Budget

Sweep uses a bounded probe set with a default cap of 350 unique probes per endpoint.
High Signal promotes the full Path attack's raw and encoded backslash primitive as prefix, suffix,
and sandwich mutations on every path segment.

Generated requests are deduplicated before sending. This matters for short paths such as `/admin`, where some templates collapse to the same effective request:

```text
//admin
///admin
```

For longer paths such as `/admin/users`, prefix slash probes and internal duplicate slash probes are distinct:

```text
//admin/users
///admin/users
/admin//users
/admin///users
```

## Probe Wordlist

Sweep probes are controlled by one explicit build-time wordlist:

```text
src/main/resources/payloads/sweep_probes.txt
```

The wordlist is intentionally visible and simple. Rows are either `PATH` or `HEADER` templates.

Examples:

```text
PATH|Matrix / Extension|Path suffix ;.json|{PATH};.json{QUERY}
PATH|Path Normalization|Uppercase first segment|{PATH_FIRST_SEGMENT_UPPERCASE}
PATH|Path Normalization|Uppercase last segment|{PATH_LAST_SEGMENT_UPPERCASE}
PATH|Encoding|Double URL encode path character 1|{PATH_DOUBLE_URL_ENCODE_CHAR_1}
PATH|Debug Params|Append debug=true|{PATH}{QUERY}{QUERY_APPEND_SEPARATOR}debug=true
HEADER|Content-Type|Content-Type application/json|Content-Type: application/json
HEADER|Header|Authorization bearer placeholder|Authorization: Bearer A
```

The supported placeholders are documented at the top of the wordlist.

## Current Probe Families

The default Sweep probes focus on:

- matrix and extension normalization
- standalone dot/semicolon boundary and per-segment surround probes, including URL-encoded, double-encoded, and legacy `%u` forms
- lightweight content negotiation query probes
- framework and extension fallback suffixes
- trailing slash toggle
- dot-segment and encoded-dot suffixes
- encoded and double-encoded dot-segment prefixes and suffixes
- prefix double and triple slash variants
- internal duplicate slash variants
- first-segment and last-segment uppercase variants
- capitalized and mixed-case path variants
- selected URL-encoded path characters
- selected double URL-encoded path characters
- selected encoded path separators and fully encoded segments
- selected debug parameters
- selected `Content-Type` header mutations
- selected lightweight header probes

## Preview

The `Preview Probes` button shows the exact requests that Sweep will send for the selected candidate.

Preview does not send traffic.

It uses the same generator path as execution, so it is the source of truth for what will run.

## Signals

Sweep shows all responses, but the `Signal` column is only populated for interesting changes.

Examples:

```text
403 -> 200
401 -> 302
Content-Type text/html -> application/json
Length +347
```

Probe responses with `4xx` status codes are still shown, but they do not receive a signal. This avoids noisy cases such as a redirect baseline becoming a larger `404` page.

## Design Intent

Sweep is meant to close broad coverage gaps without becoming a hail-mary scanner.

It should:

- cover many blocked endpoints quickly
- send a small number of high-signal probes per endpoint
- make the exact probe inventory obvious to the developer
- require preview before execution
- avoid hiding request volume behind broad playbook expansion

It should not:

- scan the entire application blindly
- run thousands of payload combinations per endpoint
- replace targeted Bypass, IDOR, or URL Validation testing
