package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpRequestData;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Context-aware neutral IDOR planner with the same stable playbook identifiers as Burp. */
public final class IdorPlanner {
    public List<PlannedRequest> plan(HttpRequestData request, String authorized, String target, int maximum) {
        if (authorized == null || authorized.isEmpty()) throw new IllegalArgumentException("Authorized identifier is required");
        if (target == null || target.isEmpty()) throw new IllegalArgumentException("Target identifier is required");
        if (authorized.equals(target)) throw new IllegalArgumentException("Authorized and target identifiers must differ");
        if (RequestRewriter.count(request, authorized) == 0) {
            throw new IllegalArgumentException("Authorized identifier was not found in the request");
        }

        HttpRequestData targetRequest = RequestRewriter.replace(request, authorized, target);
        List<PlannedRequest> output = new ArrayList<>();
        output.add(PlannedRequest.baseline(request, "idor.baseline.control"));
        output.add(PlannedRequest.baseline(targetRequest, "idor.baseline.target"));
        Map<String, List<HttpRequestData>> variants = new LinkedHashMap<>();
        variants.put("idor.path.suffix_formats", suffixes(targetRequest, target));
        variants.put("idor.path.trailing_slash", List.of(targetRequest.withRawTarget(toggleSlash(targetRequest.rawTarget()))));
        variants.put("idor.path.special_identifier_values", replacements(targetRequest, target, List.of("0", "-1", "1", "null", "undefined", "*")));
        variants.put("idor.path.dot_segments", pathDecorations(targetRequest, target));
        variants.put("idor.query.conflicting_identifiers", queryVariants(targetRequest, target, authorized));
        variants.put("idor.query.parameter_pollution", queryVariants(targetRequest, target, target));
        variants.put("idor.query.comma_separated_identifiers", replacements(targetRequest, target, List.of(authorized + "," + target, target + "," + authorized)));
        variants.put("idor.query.json_wrap", replacements(targetRequest, target, List.of("[\"" + target + "\"]", "{\"id\":\"" + target + "\"}")));
        variants.put("idor.query.identifier_aliases", aliasQuery(targetRequest, target));
        variants.put("idor.query.numeric_pivots", numeric(targetRequest, target));
        variants.put("idor.body.content_type_tampering", List.of(targetRequest.upsertHeader("Content-Type", "text/plain"), targetRequest.upsertHeader("Content-Type", "application/x-www-form-urlencoded")));
        variants.put("idor.body.json_wrap", replacements(targetRequest, target, List.of("[\"" + target + "\"]", "{\"value\":\"" + target + "\"}")));
        variants.put("idor.body.deserialization_hints", List.of(targetRequest.addHeader("X-Type", "java.lang.String"), targetRequest.addHeader("X-Object-Type", "User")));
        variants.put("idor.body.json_batch_identifiers", replacements(targetRequest, target, List.of("[\"" + authorized + "\",\"" + target + "\"]")));
        variants.put("idor.body.json_parameter_pollution", replacements(targetRequest, target, List.of(target + "\",\"id\":\"" + authorized)));
        variants.put("idor.body.json_edge_cases", replacements(targetRequest, target, List.of("null", "0", "-1", "1e0")));
        variants.put("idor.body.wildcard_identifiers", replacements(targetRequest, target, List.of("*", "%", "_")));
        variants.put("idor.body.unexpected_data_types", replacements(targetRequest, target, List.of("true", "false", "[]", "{}")));
        variants.put("idor.hybrid.trailing_control_characters", replacements(targetRequest, target, List.of(target + "%00", target + "%0a", target + "%09")));
        variants.put("idor.hybrid.empty_identifier_values", replacements(targetRequest, target, List.of("", "null", "undefined")));
        variants.put("idor.hybrid.resource_shortcuts", replacements(targetRequest, target, List.of("me", "self", "current")));
        variants.put("idor.hybrid.case_variants", replacements(targetRequest, target, List.of(target.toUpperCase(Locale.ROOT), target.toLowerCase(Locale.ROOT))));
        variants.put("idor.hybrid.canonical_identifier_formats", canonical(targetRequest, target));
        variants.put("idor.hybrid.uuid_neighbor_edits", uuidNeighbors(targetRequest, target));
        variants.put("idor.hybrid.truncated_identifier_variants", truncated(targetRequest, target));
        variants.put("idor.hybrid.uuid_version_variants", uuidVersions(targetRequest, target));
        variants.put("idor.hybrid.accept_negotiation", List.of(targetRequest.upsertHeader("Accept", "application/json"), targetRequest.upsertHeader("Accept", "text/plain"), targetRequest.upsertHeader("Accept", "*/*")));
        variants.put("idor.hybrid.cross_source_conflicts", List.of(targetRequest.addHeader("X-User-Id", authorized), targetRequest.addHeader("X-Object-Id", target)));
        variants.put("idor.hybrid.query_body_cross_source", List.of(targetRequest.withRawTarget(appendQuery(targetRequest.rawTarget(), "id=" + authorized))));
        variants.put("idor.hybrid.identifier_encoding", replacements(targetRequest, target, List.of(urlEncode(target), doubleEncode(target))));
        variants.put("idor.hybrid.method_override", List.of(targetRequest.upsertHeader("X-HTTP-Method-Override", "GET"), targetRequest.upsertHeader("X-HTTP-Method-Override", "PUT")));

        int row = 0;
        Set<String> seen = new LinkedHashSet<>();
        boolean added;
        do {
            added = false;
            for (Map.Entry<String, List<HttpRequestData>> entry : variants.entrySet()) {
                if (row >= entry.getValue().size()) continue;
                HttpRequestData mutation = entry.getValue().get(row);
                String key = mutation.toRaw();
                if (seen.add(key)) output.add(new PlannedRequest(entry.getKey(), entry.getKey() + " #" + (row + 1), "", mutation, false));
                added = true;
                if (output.size() >= Math.max(2, maximum)) return List.copyOf(output);
            }
            row++;
        } while (added);
        return List.copyOf(output);
    }

    private List<HttpRequestData> replacements(HttpRequestData request, String source, List<String> values) { return values.stream().map(value -> RequestRewriter.replace(request, source, value)).toList(); }
    private List<HttpRequestData> suffixes(HttpRequestData request, String id) { return replacements(request, id, List.of(id + ".json", id + ".xml", id + ";", id + "/")); }
    private List<HttpRequestData> pathDecorations(HttpRequestData request, String id) { return replacements(request, id, List.of("./" + id, "../" + id, "%2e/" + id, id + "/..")); }
    private List<HttpRequestData> queryVariants(HttpRequestData request, String target, String other) { return List.of(request.withRawTarget(appendQuery(request.rawTarget(), "id=" + other)), request.withRawTarget(appendQuery(request.rawTarget(), "userId=" + other))); }
    private List<HttpRequestData> aliasQuery(HttpRequestData request, String target) { return List.of("id", "user_id", "userId", "objectId", "accountId").stream().map(name -> request.withRawTarget(appendQuery(request.rawTarget(), name + "=" + target))).toList(); }
    private List<HttpRequestData> numeric(HttpRequestData request, String target) { try { long value = Long.parseLong(target); return replacements(request, target, List.of(String.valueOf(value - 1), String.valueOf(value + 1), String.valueOf(value + 10))); } catch (NumberFormatException ignored) { return List.of(); } }
    private List<HttpRequestData> canonical(HttpRequestData request, String target) { return replacements(request, target, List.of(target.replace("-", ""), target.startsWith("0") ? target.replaceFirst("^0+", "") : "0" + target)); }
    private List<HttpRequestData> uuidNeighbors(HttpRequestData request, String target) { try { UUID uuid = UUID.fromString(target); String value = uuid.toString(); char last = value.charAt(value.length() - 1); char next = Character.forDigit((Character.digit(last, 16) + 1) & 15, 16); return replacements(request, target, List.of(value.substring(0, value.length() - 1) + next)); } catch (Exception ignored) { return List.of(); } }
    private List<HttpRequestData> truncated(HttpRequestData request, String target) { List<String> values = new ArrayList<>(); for (int size : List.of(1, 2, 4, 8)) if (target.length() > size) values.add(target.substring(0, target.length() - size)); return replacements(request, target, values); }
    private List<HttpRequestData> uuidVersions(HttpRequestData request, String target) { try { UUID.fromString(target); List<String> values = new ArrayList<>(); for (char version : List.of('1', '3', '4', '5')) { StringBuilder value = new StringBuilder(target.toLowerCase(Locale.ROOT)); value.setCharAt(14, version); values.add(value.toString()); } return replacements(request, target, values); } catch (Exception ignored) { return List.of(); } }
    private String toggleSlash(String target) { int query = target.indexOf('?'); String path = query < 0 ? target : target.substring(0, query); String suffix = query < 0 ? "" : target.substring(query); return (path.endsWith("/") ? path.substring(0, path.length() - 1) : path + "/") + suffix; }
    private String appendQuery(String target, String pair) { return target + (target.contains("?") ? "&" : "?") + pair; }
    private String urlEncode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private String doubleEncode(String value) { return URLEncoder.encode(urlEncode(value), StandardCharsets.UTF_8); }
}
