# URL Validation Playbooks

The `URL Validation` tab is for marker-driven URL validation, allow-list bypass, and SSRF-style parser mismatch testing.

The main payload generation flow lives in `core/src/main/java/com/bypassfuzzer/core/urlvalidation/UrlValidationPayloadGenerator.java`.

This page follows the same style as the IDOR playbook docs: why the area exists, what categories the tool generates, representative examples, and the kinds of broken code those payloads are trying to expose.

## Why This Is In The Tool

Applications frequently accept user-controlled URLs, hosts, or origins and then try to validate them.

Those validation layers often fail because:

- they parse a URL differently from the component that later uses it
- they only validate part of the input
- they mishandle encoding
- they allow loopback, metadata, or attacker-controlled routing tricks

This tab exists to turn those families into repeatable, reviewable payload sets instead of treating URL validation bugs as one-off manual tests.

## Core Flow

The current URL validation engine does four things:

1. the user marks one or more injection points, usually with `{INJECT}`
2. the generator expands payloads using selected contexts, settings, and encodings
3. each marker is replaced with concrete payloads
4. results are emitted into the same session/results workflow as the other tabs

## Payload Contexts

These are modeled by `UrlValidationContext`.

### `Absolute URL`

### Purpose

This context exists for places that expect a full URL, such as redirect targets, callback URLs, webhooks, or SSRF targets.

### Representative Examples

```text
https://attacker.example/
http://127.0.0.1/
http://169.254.169.254/
```

### What The Broken Target Code Might Look Like

```java
String supplied = request.query("url");
if (supplied.endsWith(".trusted.example")) {
    allow();
}

return httpClient.get(new URL(supplied));
```

### `Host header`

### Purpose

This context exists for places that validate only a hostname instead of a full URL.

### Representative Examples

```text
trusted.example.attacker.example
127.0.0.1
[::1]
```

### What The Broken Target Code Might Look Like

```java
String host = request.header("Host");
if (host.contains("trusted.example")) {
    allow();
}

proxyTo(host);
```

### `CORS`

### Purpose

This context exists for places that make trust decisions based on `Origin` matching.

### Representative Examples

```http
Origin: https://trusted.example.attacker.example
Origin: null
Origin: https://trusted.example%00.attacker.example
```

### What The Broken Target Code Might Look Like

```java
String origin = request.header("Origin");
if (origin.endsWith("trusted.example")) {
    response.header("Access-Control-Allow-Origin", origin);
}
```

## Payload Categories

These are modeled by `UrlValidationAttackSetting`.

### `Domain allow list bypass`

### Purpose

This family exists because many validators trust a URL or host if it appears to match an allowed domain, but the downstream parser resolves it differently.

### Representative Examples

```text
https://trusted.example.attacker.example/
https://trusted.example@attacker.example/
https://trusted.example%00.attacker.example/
```

### What The Broken Target Code Might Look Like

```java
if (input.contains("trusted.example")) {
    allow();
}

URL url = new URL(input);
fetch(url);
```

### `Fake relative URLs`

### Purpose

This family exists because some parsers misread authority, slashes, or relative-looking payloads.

### Representative Examples

```text
https:attacker.example
//attacker.example
\/\attacker.example
```

### What The Broken Target Code Might Look Like

```java
if (!input.startsWith("http://") && !input.startsWith("https://")) {
    treatAsRelative(input);
}

return browserLikeParser.resolve(input);
```

### `Loopback`

### Purpose

This family exists because applications often try to block localhost access but miss alternate loopback forms.

### Representative Examples

```text
http://127.0.0.1/
http://localhost/
http://2130706433/
http://0177.0.0.1/
```

### What The Broken Target Code Might Look Like

```java
if ("127.0.0.1".equals(host)) {
    deny();
}

return httpClient.get(input);
```

### `IPv6`

### Purpose

This family exists because IPv6 parsing and normalization often differ between validators and downstream clients.

### Representative Examples

```text
http://[::1]/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:7f00:1]/
```

### What The Broken Target Code Might Look Like

```java
if (host.startsWith("127.")) {
    deny();
}

InetAddress address = InetAddress.getByName(host);
connect(address);
```

### `Cloud metadata endpoints`

### Purpose

This family exists because SSRF defenses often forget cloud metadata IPs and hostnames.

### Representative Examples

```text
http://169.254.169.254/
http://metadata.google.internal/
http://100.100.100.200/
```

### What The Broken Target Code Might Look Like

```java
if (isPrivateRfc1918(host)) {
    deny();
}

return fetch(input);
```

### `URL-splitting Unicode characters`

### Purpose

This family exists because Unicode separators and split characters are not always handled consistently across validators, app frameworks, and downstream clients.

### Representative Examples

```text
https://trusted.example%E3%80%82attacker.example/
https://trusted.example%E2%81%84attacker.example/
```

### What The Broken Target Code Might Look Like

```java
if (input.endsWith(".trusted.example")) {
    allow();
}

String normalized = unicodeNormalize(input);
fetch(normalized);
```

## Encoding Modes

### Purpose

The generator can render payloads in different encodings before insertion because some validators inspect raw input while downstream components decode it one or more times.

### Representative Examples

```text
https%3A%2F%2Fattacker.example%2F
https%253A%252F%252Fattacker.example%252F
```

### What The Broken Target Code Might Look Like

```java
if (input.contains("trusted.example")) {
    allow();
}

String decoded = urlDecode(urlDecode(input));
fetch(decoded);
```

## Notes

- This area is payload-family-driven rather than attack-type-driven.
- The source payloads are bundled resources rather than hardcoded inline lists.
- The examples above are representative, not exhaustive.
- The current implementation is intentionally aligned with the PortSwigger URL validation bypass cheatsheet model.
