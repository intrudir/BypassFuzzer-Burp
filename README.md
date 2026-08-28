# BypassFuzzer — Burp Suite and CLI

An authorization-bypass fuzzer available as both a Burp Suite extension and a standalone Java/Docker CLI. Both surfaces use the same payload resources and transport-neutral Bypass planner.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Burp Suite extension](#burp-suite-extension)
  - [Standalone CLI](#standalone-cli)
  - [Docker](#docker)
  - [Building from source (optional)](#building-from-source-optional)
- [CLI usage](#cli-usage)
  - [Sweep](#sweep)
  - [Targeted bypass](#targeted-bypass)
  - [IDOR / BOLA](#idor--bola)
  - [URL validation](#url-validation)
  - [Runtime controls](#runtime-controls)
  - [YAML jobs](#yaml-jobs)
  - [Results and evidence](#results-and-evidence)
- [Burp Suite usage](#burp-suite-usage)
  - [Basic Workflow](#basic-workflow)
  - [Sweep Tab](#sweep-tab)
  - [Bypass Tab](#bypass-tab)
  - [URL Validation tab](#url-validation-tab)
- [Documentation](#documentation)
- [Custom Payloads](#custom-payloads)
- [License](#license)
- [Credits](#credits)

## Features
BypassFuzzer has four main testing areas:

- **Sweep** for broad, bounded coverage of in-scope Proxy-history responses such as `401` and `403`.
- **Bypass** for targeted authorization bypass testing against a request you send to BypassFuzzer.
- **IDOR** for object identifier and BOLA-style request mutation.
- **URL Validation** for marker-driven URL validation and SSRF-style allow-list bypass testing.

All four modes are available from the CLI. Sweep accepts URL lists, raw-request manifests, OpenAPI/Swagger, Postman, and Burp version-1 retry packages. Proxy history and Burp Collaborator remain desktop-only.

- **Standalone CLI:**
  - Runs as a Java fat JAR or a locally built non-root Docker image
  - Provides `sweep`, `bypass`, `idor`, and `url-validation` commands
  - Uses the same Bypass planner and bundled payload resources as the Burp extension
  - Preserves raw request targets, ordered duplicate headers, and request bodies
  - Keeps the network destination separate from the fuzzable `Host` header
  - Supports HTTP/1.0, HTTP/1.1, native HTTP/2, cleartext h2c, and ALPN negotiation
  - Streams JSONL results while retaining raw request and response evidence for every probe
  - Supports strict versioned YAML jobs with command-line flags taking precedence
  - Excludes Burp Collaborator and all out-of-band payload generation

- **Sweep Mode:**
  - Available immediately when the extension loads
  - Pulls in-scope Proxy history by response status, defaulting to `401` and `403`
  - Can identify authenticated `2xx` history by selected auth headers/cookies and attack credential-stripped request copies
  - Can verify credential-stripped controls and highlight `LIKELY PUBLIC` candidates for focused review
  - Excludes images, JavaScript, CSS, and WOFF responses from authenticated-traffic discovery by default, with a checkbox to include them
  - Imports `.txt` target lists with one absolute URL per line
  - Imports OpenAPI 3 and Swagger 2 JSON/YAML specifications as method-aware sweep candidates
  - Imports Postman Collection v2.0/v2.1 JSON, preserving methods, parameters, headers, auth, and request bodies
  - Deduplicates endpoint shapes before sending probes
  - Uses a bounded, mile-wide/inch-deep probe set with a default cap of 350 probes per endpoint
  - Adaptive per-host rate control: automatically discovers each host's rate-limit ceiling and rides just under it (no delay/rate knobs to tune), sweeping every host in parallel at its own speed
  - Optional one-click browser User-Agent preset on sweep probes
  - Shared request-header controls in every mode, including optional per-request User-Agent variation with synthetic non-browser tokens or browser-like variants
  - Shared full throttle controls and a common deferred retry queue across Bypass, Sweep, IDOR, and URL Validation
  - Includes a preview table and exact probe preview before sending requests
  - Uses an explicit build-time wordlist at `src/main/resources/payloads/sweep_probes.txt`
  - Shows concrete signals such as `403 -> 200` and suppresses noisy `4xx` probe signals

- **AuthZ Bypass Attack Types:**
  - Header-based attacks (283+ bypass headers)
  - Path manipulation (367+ URL encodings)
  - HTTP verb/method attacks (11 methods + overrides + case variations + X-prefix/suffix)
  - Debug parameter injection (31 common debug params with case variations)
  - Cookie debug parameter injection (same params as cookies + fuzz existing cookie values)
  - Trailing dot attack (absolute domain notation)
  - Trailing slash attack (tests with/without trailing slash and /. pattern)
  - Extension attack (75+ file extensions like .json, .html, .php)
  - Content-Type attack (converts between URL-encoded, JSON, XML, multipart/form-data)
  - Encoding attack (URL, double-URL, triple-URL, unicode, unicode-overflow encoding on paths, parameter names, and parameter values in query strings and all body content types)
  - HTTP protocol attacks (e.g. HTTP/1.0, HTTP/0.9)
  - Case variation attack (random capitalizations with smart limits)
- **Dedicated URL Validation Tab:**
  - URL Validation playbooks based on the [Portswigger Cheatsheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
  - Mark your injection points with `{INJECT}`
  - Includes a `View Payloads` preview for the exact generated list before execution
- **Smart Filtering:** Automatically reduces noise by hiding repeated responses with pattern tracking
- **Adaptive Rate Control:**
  - One controller per host discovers that host's rate-limit ceiling and rides just under it, maximizing throughput while keeping throttles rare
  - AIMD control law with slow-start; honors `Retry-After`; throttled requests are auto-retried so coverage stays complete
  - Configurable rate-limit status codes (default: 429, 503); no manual delay or requests-per-second tuning
- **Collaborator Integration:** Dynamic Burp Collaborator payload generation to watch for out-of-band interactions (Burp Professional only)

## Requirements

- Java 17 or higher for the JAR distribution
- Docker to build and run the container locally
- Burp Suite Professional or Community Edition (2023.10+) for the desktop extension only
- Internet access on the first build if Java 17+ is not already installed (the build helper downloads a project-local Temurin JDK)

## Installation

### Burp Suite extension

1. Download latest JAR from the [releases page](https://github.com/intrudir/BypassFuzzer-Burp/releases)
2. In Burp, go to **Extensions** → **Installed**
3. Click **Add**
4. Select **Extension file**: `bypassfuzzer.jar`
5. The extension will load and a "BypassFuzzer" tab will appear

### Standalone CLI

Download `bypassfuzzer-cli.jar` from the [latest release](https://github.com/intrudir/BypassFuzzer-Burp/releases/latest), then run:

```bash
java -jar bypassfuzzer-cli.jar --version
java -jar bypassfuzzer-cli.jar --help
```

### Docker

Build the CLI image locally from the repository:

```bash
docker build -t bypassfuzzer:1.4.2 .

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" \
  bypassfuzzer:1.4.2 \
  sweep --urls /work/targets.txt --output /work/output/sweep
```

The image runs without root privileges. Mount input and output paths beneath `/work`.

### Building from source (optional)

```bash
# Build the extension JAR (macOS/Linux)
sh build.sh clean shadowJar

# The compiled JAR will be at:
# build/libs/bypassfuzzer.jar

# Build the standalone CLI JAR:
./gradlew :cli:shadowJar
# cli/build/libs/bypassfuzzer-cli.jar
```

On Windows PowerShell, run `.\build.ps1 clean shadowJar`. On systems where the shell does not preserve executable bits, run `sh build.sh clean shadowJar`. These helpers use an existing Java 17+ installation when available. Otherwise they download Temurin 17 into `.gradle/jdks` and reuse it on later builds. You can still invoke `./gradlew` or `gradlew.bat` directly when Java is already configured.

Builds embed the public S3 version manifest URL by default so BypassFuzzer can notify users when a newer release is available. Override it for custom release channels with `-PupdateManifestUrl=...`. To preview the update banner locally without changing S3, build with `-PdevLatestVersion=1.4.2`.

## CLI usage

Only run active fuzzing against systems you are authorized to test. The examples below use the locally built JAR; replace `cli/build/libs/bypassfuzzer-cli.jar` with the path to a downloaded release JAR if needed.

Create a URL list with one absolute HTTP or HTTPS URL per line:

```text
https://app.example/admin
https://api.example/v1/reports/quarterly?format=json
```

For Bypass, IDOR, and URL Validation, save the exact HTTP request you want to mutate. For example, `blocked.raw`:

```http
GET /admin/reports HTTP/1.1
Host: app.example
Authorization: Bearer replace-with-your-token
Accept: application/json

```

Raw requests require `--target-origin`. This is the real socket and TLS destination and must contain only the scheme, host, and optional port. A payload that changes `Host` or the request target will not silently redirect the scanner to another server.

### Sweep

High Signal is the default bounded Sweep corpus. It is the best starting point for broad coverage:

```bash
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep \
  --urls targets.txt \
  --payload-set high-signal \
  --max-probes 80 \
  --global-concurrency 10 \
  --per-host-concurrency 5 \
  --header 'Authorization: Bearer replace-with-your-token' \
  --redact \
  --output output/sweep-high-signal
```

URL-list inputs do not carry authentication. Add repeatable `--header` options for the authorization and session headers the application expects.

To restrict High Signal categories, use their exact names:

```bash
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep \
  --urls targets.txt \
  --payload-set high-signal \
  --families 'Header,Path Normalization,Encoding' \
  --output output/sweep-selected
```

The available High Signal categories are `Matrix / Extension`, `Extension / Negotiation`, `Path Normalization`, `Encoding`, `Debug Params`, `Content-Type`, `Header`, and `Host Parsing`.

Use `all` to run the full shared Bypass inventory. Restrict it to selected stable family IDs when you do not need every mutation:

```bash
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep \
  --urls targets.txt \
  --payload-set all \
  --families header,path,verb,encoding,protocol \
  --max-probes 500 \
  --redact \
  --output output/sweep-all
```

The twelve all-payload family IDs are:

```text
header,path,verb,param,cookie,trailingdot,trailingslash,extension,contenttype,encoding,protocol,case
```

Sweep accepts exactly one input source per run:

```bash
# One absolute URL per line
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep \
  --urls targets.txt --output output/urls

# One raw request
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep \
  --request blocked.raw --target-origin https://app.example \
  --output output/raw-request

# OpenAPI or Swagger, from a local file or HTTPS URL
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep \
  --openapi openapi.yaml --base-url https://api.example \
  --output output/openapi

# Postman Collection v2.0/v2.1
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep \
  --postman collection.json --base-url https://api.example \
  --output output/postman

# A retry package exported by the Burp Sweep UI
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep \
  --retry-package bypassfuzzer-retry-queue.json \
  --output output/retry-package
```

OpenAPI and Postman imports exclude `POST`, `PUT`, `PATCH`, and `DELETE` by default. Include them only when those state-changing operations are explicitly in scope:

```bash
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep \
  --openapi openapi.yaml \
  --base-url https://api.example \
  --include-state-changing \
  --output output/openapi-all-methods
```

A request manifest can hold several raw requests. Paths are relative to the manifest file:

```yaml
requests:
  - requestFile: requests/admin.raw
    targetOrigin: https://app.example
  - requestFile: requests/report.raw
    targetOrigin: https://api.example
```

Run it with:

```bash
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep \
  --request-manifest requests.yaml \
  --payload-set high-signal \
  --output output/request-manifest
```

### Targeted bypass

Run selected attack families against one blocked request:

```bash
java -jar cli/build/libs/bypassfuzzer-cli.jar bypass \
  --request blocked.raw \
  --target-origin https://app.example \
  --families header,path,verb,param,cookie,encoding \
  --max-probes 1000 \
  --redact \
  --output output/bypass
```

Add `--fuzz-existing-cookies` when the request contains cookies whose current values should also be mutated:

```bash
java -jar cli/build/libs/bypassfuzzer-cli.jar bypass \
  --request blocked.raw \
  --target-origin https://app.example \
  --families cookie \
  --fuzz-existing-cookies \
  --output output/cookie-bypass
```

### IDOR / BOLA

The authorized identifier must appear as an exact literal in the request. The CLI sends the authorized control and target-identifier baseline before its path, query, body, and hybrid playbooks:

```http
GET /api/users/100/orders?userId=100 HTTP/1.1
Host: api.example
Authorization: Bearer replace-with-your-token

```

```bash
java -jar cli/build/libs/bypassfuzzer-cli.jar idor \
  --request object.raw \
  --target-origin https://api.example \
  --authorized-id 100 \
  --target-id 200 \
  --max-probes 500 \
  --redact \
  --output output/idor
```

Always compare a possible finding with both baseline records before treating it as an authorization issue.

### URL validation

Put the literal marker `{INJECT}` wherever a generated URL payload should be inserted:

```http
GET /redirect?next={INJECT} HTTP/1.1
Host: app.example
Authorization: Bearer replace-with-your-token

```

Run an absolute-URL allow-list scenario:

```bash
java -jar cli/build/libs/bypassfuzzer-cli.jar url-validation \
  --request redirect.raw \
  --target-origin https://app.example \
  --marker '{INJECT}' \
  --allowed-host trusted.example \
  --attacker-host attacker.example \
  --contexts absolute-url \
  --attacks domain-allow-list-bypass \
  --encodings raw,intruders \
  --max-probes 500 \
  --redact \
  --output output/url-validation
```

Available contexts are `absolute-url`, `host-header`, and `cors`.

Available attack IDs are:

```text
domain-allow-list-bypass,fake-relative-urls,loopback,ipv6,cloud-metadata-endpoints,url-splitting-unicode-characters,normalization-attack
```

Available encoding IDs are:

```text
raw,intruders,everything,special-chars,unicode-escape
```

The CLI requires an explicit attacker host and never creates Burp Collaborator or other out-of-band payloads.

### Runtime controls

The four commands share transport, concurrency, retry, header, and evidence controls. For example:

```bash
java -jar cli/build/libs/bypassfuzzer-cli.jar bypass \
  --request blocked.raw \
  --target-origin https://app.example \
  --protocol both \
  --proxy http://127.0.0.1:8080 \
  --connect-timeout 10 \
  --request-timeout 20 \
  --global-concurrency 10 \
  --per-host-concurrency 4 \
  --throttle-codes 429,503 \
  --retry-attempts 2 \
  --posture conservative \
  --pause-mode smart \
  --fixed-pause-ms 30000 \
  --header 'X-Assessment-ID: authorized-run-42' \
  --user-agent-mode synthetic \
  --user-agent-seed 42 \
  --redact \
  --output output/bypass-controlled
```

Protocol modes:

- `auto`: HTTPS negotiates HTTP/2 or HTTP/1 with ALPN; cleartext uses HTTP/1.
- `http1`: HTTP/1.1, except payloads that deliberately select another HTTP/1 version.
- `http2`: native HTTP/2 over TLS or h2c prior knowledge for cleartext targets.
- `both`: runs the baseline and generated probes over HTTP/1.1 and HTTP/2.

Use `--insecure` only when an authorized target intentionally uses an untrusted TLS certificate. Proxy URLs use `http://[user:password@]host:port` syntax.

### YAML jobs

Every mode accepts a strict version-1 YAML job. This example runs Bypass:

```yaml
schemaVersion: 1
input:
  request: requests/admin.raw
  targetOrigin: https://app.example
transport:
  protocol: auto
  requestTimeoutSeconds: 20
  connectTimeoutSeconds: 10
execution:
  globalConcurrency: 10
  perHostConcurrency: 5
  throttleStatusCodes: [429, 503]
  retryAttempts: 1
  maxProbes: 750
  posture: conservative
  pauseMode: smart
  fixedPauseMillis: 30000
  headers:
    - 'X-Assessment-ID: authorized-run-42'
evidence:
  output: output/admin-run
  redact: true
bypass:
  families: [header, path, verb, encoding]
  fuzzExistingCookies: false
```

```bash
java -jar cli/build/libs/bypassfuzzer-cli.jar bypass --config job.yaml
```

Paths in YAML resolve relative to the YAML file. Command-line flags override YAML values, and YAML overrides built-in defaults. Unknown keys are rejected. Any key containing `collaborator` is also rejected because Collaborator is not part of the CLI.

### Results and evidence

Results stream as one JSON object per line on stdout, while progress goes to stderr. Save the stream separately if another tool will consume it:

```bash
mkdir -p output
java -jar cli/build/libs/bypassfuzzer-cli.jar sweep \
  --urls targets.txt \
  --output output/sweep \
  > output/sweep-results.jsonl
```

Each output directory contains:

```text
run.json
results.jsonl
summary.json
requests/000001-request.raw
responses/000001-response.raw
```

Read the final state and inspect a referenced request/response pair:

```bash
sed -n '1,160p' output/sweep/summary.json
sed -n '1,160p' output/sweep/requests/000001-request.raw
sed -n '1,160p' output/sweep/responses/000001-response.raw
```

Useful result signals include `LIKELY_BYPASS`, `RESPONSE_CHANGED`, `THROTTLED`, `NO_SIGNAL`, and `NO_RESPONSE`. A signal is triage evidence, not a vulnerability verdict.

Raw evidence can contain credentials. Use `--redact` to mask common credential headers in stored evidence without changing the requests sent on the wire. Preflight and usage errors return exit code `2`; once a scan starts, automation should read `summary.json` for final state and findings.

## Burp Suite usage

### Basic Workflow

1. **Send Request to BypassFuzzer:**
   - In Proxy, Sitemap, or Repeater, find any 403/401, any suspiciously blocked request
   - Right-click request 
   - Select `Send to BypassFuzzer`, then choose `Bypass`, `IDOR`, or `URL Validation`
![](images/image1.png)
2. **Open the Request Session:**
   - `Sweep` for broad coverage of blocked endpoints found in Proxy history
   - The request opens as a closeable tab beneath the mode you selected
   - `Bypass` runs the core AuthZ bypass playbooks
   - `IDOR` runs object identifier and BOLA-style mutations
   - `URL Validation` runs marker-driven URL validation testing
![](images/image2.png)

### Dashboard

The `Dashboard` is the master control plane for every open Sweep, Bypass, IDOR, and URL Validation
activity. It shows current state and progress, opens the corresponding request tab, and provides
per-row Pause/Resume and Stop actions. `Pause All` blocks new BypassFuzzer requests without changing
which sessions were already paused locally; `Resume All` therefore leaves those sessions paused.
`Stop All` stops active scans and retry passes after confirmation without closing tabs or results.

Optional extension-wide safety limits apply across all tabs and retry passes. Enable them on the
Dashboard and set a smooth maximum requests/second for each host plus a maximum total number of
in-flight requests. They start disabled with suggested values of 10 req/s per host and 10 in-flight,
apply immediately, and reset whenever Burp restarts.

### Sweep Tab

The `Sweep` tab is available as soon as the extension loads. It supports a bounded High Signal pass or the complete selected Bypass payload inventory across blocked endpoints and imported targets.

**Workflow**

1. Select a Sweep mode:
   - `Blocked responses` to load Proxy history by status
   - `Authenticated traffic` to load credential-bearing `2xx` Proxy history
   - `Import targets` to load a `.txt` URL list, OpenAPI/Swagger specification, or Postman collection
2. In `Blocked responses`, select which Proxy history responses to load:
   - `401` and `403` are selected by default
   - `3xx` and `4xx` can be included when you intentionally want broader coverage
3. Use the load/import button shown for the selected mode
4. Review the deduped candidate table
   - Use **View** to open the selected request and response side by side
5. Uncheck candidates you do not want to probe
6. Adjust global/per-host concurrency and throttle status codes if needed. Every mode's shared `Throttle...` dialog also provides a fixed
   run-wide cooldown or Smart Pause for shared CDN/WAF rate limits. Smart Pause tolerates isolated
   throttles, detects sustained per-host or correlated multi-host saturation, and cautiously probes
   recovery before resuming full flow while honoring `Retry-After`.
7. Choose **High signal** for the curated bounded corpus or **All payloads** for every payload in the selected Bypass families
8. Use **Payload Families...** to disable any High Signal categories or full Bypass attack families you do not want to send
9. Use **Preview Probes** to inspect the exact requests that will be sent for a selected candidate
10. Click **Start Sweep**

**Pause/Resume:** Pause stops new network sends and freezes throttle admission. Responses from
already-sent requests may still arrive. Resume discards accumulated burst credit; after a pause of
30 seconds or longer, each host restarts at the safe initial adaptive rate without losing scan
position or queued retries.

**What Sweep sends**

High Signal uses a curated wordlist capped at 350 probes per endpoint by default. The bundled wordlist focuses on:

- raw and encoded backslash prefix, suffix, and sandwich mutations on every path segment
- matrix and extension normalization such as `;.json`, `;.html`, `.json;`, and `.html;`
- standalone dot/semicolon markers inserted at boundaries and around each segment, including URL-encoded, double-encoded, and legacy `%u` forms
- lightweight content negotiation query probes such as `?.json` and `?format=json`
- framework and extension fallback suffixes such as `.php`, `.aspx`, `.jsp`, `.map`, `.bak`, `.old`, and `.config`
- trailing slash and dot-segment normalization
- encoded and double-encoded dot-segment probes
- double and triple slash variants
- segment-level case variants such as `/ADMIN/users` and `/admin/USERS`
- deterministic mixed-case variants
- selected URL-encoded and double URL-encoded path-character variants
- selected fully encoded segment and encoded path-separator variants
- selected debug parameters such as `debug=true`, `debug=1`, `admin=1`, `isAdmin=true`, `role=admin`, and `user=admin`
- selected `Content-Type` probes such as `application/json`, `application/x-www-form-urlencoded`, `multipart/form-data`, and XML/text variants
- selected lightweight header probes such as `X-Forwarded-For` and placeholder `Authorization` values

All Payloads runs the complete catalog from every selected Bypass family. It is not truncated by
the High Signal per-endpoint cap. Sweep generates that catalog only when a worker is ready for an
endpoint, so a large run does not hold every endpoint's mutated requests in memory at once. Global
and per-host concurrency are hard in-flight limits: a value of `2` creates at most two active Sweep
workers, rather than being silently raised.

All selected payloads continue until they complete or you press **Stop**. Results are delivered to
the Swing UI in bounded batches, and per-probe raw request/response evidence uses Burp's
temp-file-backed message storage. The table and exports still expose the complete evidence while
large response bodies do not accumulate on the Java heap.

Sweep results show all responses. The `Signal` column is reserved for concrete interesting changes, such as:

- `403 -> 200`
- `401 -> 302`
- `Content-Type text/html -> application/json`
- `Length +347`

Probe responses with `4xx` status codes are still shown, but they are not marked with a signal.
If Burp receives no response, Sweep retries safe `GET`/`HEAD` probes over HTTP/1 and labels any remaining transport failure as `No response` in the results table and extension error log.

### Bypass Tab

**Configure the attack**
![bypass tab](/images/bypass_tab.png)
1) Select attack types to enable (or use Check All/Uncheck All)

2) Optionally:
   - Enable Collaborator payloads (Burp Professional only)
   - Configure hard global/per-host in-flight concurrency caps
   - Configure rate-limit status codes (default: 429, 503); pacing is automatic and adaptive

3) Manual & Smart filter
   - manual filter lets you choose various options to find what you want
   - smart filter auto mutes uninteresting responses for you

4) Results table, sortable columns

5) Inspect a result's request & response
     
**Start Fuzzing**
   - Click the **Start Fuzzing** button
   - Results appear in real-time, filtered with your criteria in real-time
   - Every HTTP outcome is retained, including `429`/`503` throttle responses. Automatic attempts are
     labeled `[throttle retry #N]`; requests that remain throttled stay in the shared **Retry queue**
   - Can stop fuzzing at any time with the `Stop` button
   - Adaptive rate control paces each session automatically; use Dashboard hard limits when several
     sessions share the same API quota
   - Progress reports payloads planned, actual HTTP requests sent, results recorded, and deferred
     retries separately; a result row number is not treated as a network-send counter
   - Can right click a request to color it for identification/filtering later

**Scan History:**
   - Export results to CSV/JSON (TODO)

### URL Validation tab
**Configure the attack**
![URL validation tab](/images/url_vali_tab.png)
1) Configure Attack button opens configuration window

2) Add the `{INJECT}` marker wherever generated payloads should be inserted in the request.

3) Add the allow-listed host and your attacker-controlled domain or SSRF target. The tool generates parser and allow-list bypass variations from these values.

4) Select the context, payload families, and encoding options appropriate to a CORS/origin header, hostname, or full URL with a scheme.

5) Click **Start URL Validation**. The configuration window closes and results begin streaming into the session.

## Documentation

Wiki-style project documentation lives under [`wiki/`](wiki/), including:

- [`docs/CLI.md`](docs/CLI.md) for the complete standalone CLI reference
- [`wiki/Home.md`](wiki/Home.md)
- [`wiki/Playbooks-Overview.md`](wiki/Playbooks-Overview.md)
- [`wiki/Coverage-Sweep-Mode.md`](wiki/Coverage-Sweep-Mode.md)
- [`wiki/AuthZ-Bypass-Playbooks.md`](wiki/AuthZ-Bypass-Playbooks.md)
- [`wiki/URL-Validation-Playbooks.md`](wiki/URL-Validation-Playbooks.md)
- [`wiki/IDOR-BOLA-Playbooks.md`](wiki/IDOR-BOLA-Playbooks.md)
- [`wiki/Adding-New-Playbooks.md`](wiki/Adding-New-Playbooks.md)

GitHub's Wiki tab is a separate Git repository. In this project, `wiki/` is the source of truth in the main repo, and you can mirror it into the GitHub wiki with:

```bash
./scripts/publish-wiki.sh --push
```

The script clones or updates `../BypassFuzzer-Burp.wiki`, syncs the Markdown pages from `wiki/`, and pushes them to the GitHub wiki repo.

## Custom Payloads

You can edit the payload files before building. UI config for this will be added in a future release.

Sweep uses an explicit build-time probe wordlist:

- `src/main/resources/payloads/sweep_probes.txt`

Each Sweep row is either a `PATH` or `HEADER` template:

```text
PATH|Path Normalization|Uppercase first segment|{PATH_FIRST_SEGMENT_UPPERCASE}
PATH|Debug Params|Append debug=true|{PATH}{QUERY}{QUERY_APPEND_SEPARATOR}debug=true
HEADER|Header|Authorization bearer placeholder|Authorization: Bearer A
```

The file documents all supported placeholders at the top. Edit it before building if you want to change the default Sweep probes shipped in the extension.

1. **Header Templates:** One template per line, use placeholders:
   - `{IP PAYLOAD}` - Replaced with IP addresses from ip_payloads.txt
   - `{URL PAYLOAD}` - Replaced with full target URL
   - `{PATH PAYLOAD}` - Replaced with URL path only
   - `{PATH SWAP}` - For URL-based access control bypasses; puts original path in header and swaps request path to `/`
   - `{OOB PAYLOAD}` - Dynamically generates Burp Collaborator payload (http:// and https:// URLs)
   - `{OOB DOMAIN PAYLOAD}` - Dynamically generates Burp Collaborator domain only
   - `{WHITESPACE PAYLOAD}` - Replaced with whitespace character

   Example: `X-Forwarded-For: {IP PAYLOAD}`
   Example with Collaborator: `X-Forwarded-For: {OOB DOMAIN PAYLOAD}`
   Example for URL bypass: `X-Original-URL: {PATH SWAP}` (sends `GET /` with header `X-Original-URL: /edge/private/reports/quarterly`)

   Collaborator placeholders are expanded only by the Burp extension. The standalone CLI skips OOB templates.

2. **IP Payloads:** One IP address per line

   Example: `127.0.0.1`

3. **URL Payloads:** One URL encoding/pattern per line

   Example: `/../`

4. **Parameter Payloads:** One parameter=value per line

   Example: `debug=true`

## Syncing with Upstream

The URL Validation tab is driven by the PortSwigger [`url-cheatsheet-data`](https://github.com/PortSwigger/url-cheatsheet-data) repository, mirrored into [`src/main/resources/payloads/url_validation_source_data.json`](src/main/resources/payloads/url_validation_source_data.json).

To pull the latest payloads from upstream:

```bash
python3 scripts/sync-url-cheatsheet.py
```

The script clones the upstream repo, rebuilds the source JSON, and reports what changed. Review the generated payload diff before committing it.

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Credits

- Original Python tool: [@intrudir](https://twitter.com/intrudir)
- Smart filter algorithm: [@defparam](https://twitter.com/defparam)
- Unicode overflow technique: [PortSwigger Research](https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows)
- Portswigger for the URL validation cheatsheet
