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
    public static final String NUMERIC_PIVOTS_FAMILY = "idor.query.numeric_pivots";
    public static final String SPECIAL_IDENTIFIER_VALUES_FAMILY = "idor.path.special_identifier_values";
    public static final String JSON_EDGE_CASES_FAMILY = "idor.body.json_edge_cases";
    public static final String CANONICAL_IDENTIFIER_FORMATS_FAMILY =
        "idor.hybrid.canonical_identifier_formats";
    public static final String TRUNCATED_IDENTIFIER_VARIANTS_FAMILY =
        "idor.hybrid.truncated_identifier_variants";
    public static final String NUMERIC_PIVOTS_RISK =
        "Numeric pivots try nearby identifiers beyond the two you entered. "
            + "Those identifiers may belong to other users or be outside your test scope.";
    private static final Map<String, String> DANGEROUS_FAMILY_RISKS = Map.of(
        NUMERIC_PIVOTS_FAMILY, NUMERIC_PIVOTS_RISK,
        SPECIAL_IDENTIFIER_VALUES_FAMILY,
        "Special identifier values replace the selected ID with values such as 0, 1, and -1. "
            + "They may identify other users' objects or be outside your test scope.",
        JSON_EDGE_CASES_FAMILY,
        "JSON edge cases replace a JSON identifier with values such as 0, -1, and 1e0. "
            + "They may identify other users' objects or be outside your test scope.",
        CANONICAL_IDENTIFIER_FORMATS_FAMILY,
        "Canonical identifier formats can strip leading zeros, so an ID such as 0001 may become 1. "
            + "The resulting ID may identify another user's object.",
        TRUNCATED_IDENTIFIER_VARIANTS_FAMILY,
        "Truncated identifier variants shorten the selected ID, so an ID such as 1000 may become 1. "
            + "The resulting ID may identify another user's object.");
    private static final List<String> FAMILY_IDS = List.of(
        "idor.path.suffix_formats", "idor.path.trailing_slash", "idor.path.special_identifier_values",
        "idor.path.dot_segments", "idor.query.conflicting_identifiers", "idor.query.parameter_pollution",
        "idor.query.comma_separated_identifiers", "idor.query.json_wrap", "idor.query.identifier_aliases",
        NUMERIC_PIVOTS_FAMILY, "idor.body.content_type_tampering", "idor.body.json_wrap",
        "idor.body.deserialization_hints", "idor.body.json_batch_identifiers",
        "idor.body.json_parameter_pollution", "idor.body.json_edge_cases", "idor.body.wildcard_identifiers",
        "idor.body.unexpected_data_types", "idor.hybrid.trailing_control_characters",
        "idor.hybrid.empty_identifier_values", "idor.hybrid.resource_shortcuts", "idor.hybrid.case_variants",
        CANONICAL_IDENTIFIER_FORMATS_FAMILY, "idor.hybrid.uuid_neighbor_edits",
        TRUNCATED_IDENTIFIER_VARIANTS_FAMILY, "idor.hybrid.uuid_version_variants",
        "idor.hybrid.accept_negotiation", "idor.hybrid.cross_source_conflicts",
        "idor.hybrid.query_body_cross_source", "idor.hybrid.identifier_encoding",
        "idor.hybrid.method_override", PairedControlSeparatorPlanner.FAMILY,
        ResponseGuidedIdorPlanner.FAMILY);

    public record SeparatorCoverage(int planned, int eligible, List<String> notes) { }

    public SeparatorCoverage separatorCoverage(HttpRequestData request, IdorPlanOptions options,
                                               List<PlannedRequest> planned) {
        if (!options.families().isEmpty()
            && !options.families().contains(PairedControlSeparatorPlanner.FAMILY)) return null;
        IdentifierLocation location = IdentifierLocation.discover(request, options.authorizedId()).stream()
            .filter(item -> options.locationKey() == null || item.key().equals(options.locationKey()))
            .findFirst().orElseThrow(() -> new IllegalArgumentException("Identifier location not found"));
        var inventory = new PairedControlSeparatorPlanner().inventory(request, location,
            options.authorizedId(), options.targetId());
        return new SeparatorCoverage((int) planned.stream().filter(item ->
            item.family().equals(PairedControlSeparatorPlanner.FAMILY)).count(),
            inventory.candidates().size(), inventory.notes());
    }

    public List<String> availableFamilies() { return FAMILY_IDS; }
    public Map<String, String> dangerousFamilyRisks() { return DANGEROUS_FAMILY_RISKS; }
    public List<String> defaultFamilies() {
        return FAMILY_IDS.stream().filter(family -> !DANGEROUS_FAMILY_RISKS.containsKey(family)).toList();
    }

    public List<PlannedRequest> plan(HttpRequestData request, String authorized, String target, int maximum) {
        return plan(request, new IdorPlanOptions(authorized, target, null, Set.of(), Math.max(0, maximum - 2), false));
    }

    public List<PlannedRequest> plan(HttpRequestData request, IdorPlanOptions options) {
        for (String family : options.families())
            if (!FAMILY_IDS.contains(family)) throw new IllegalArgumentException("Unknown IDOR family: " + family);
        Set<String> selectedFamilies = options.families().isEmpty()
            ? Set.copyOf(defaultFamilies()) : options.families();
        String authorized = options.authorizedId();
        String target = options.targetId();
        if (authorized == null || authorized.isEmpty()) throw new IllegalArgumentException("Authorized identifier is required");
        if (target == null || target.isEmpty()) throw new IllegalArgumentException("Target identifier is required");
        if (authorized.equals(target)) throw new IllegalArgumentException("Authorized and target identifiers must differ");
        List<IdentifierLocation> locations = IdentifierLocation.discover(request, authorized);
        IdentifierLocation location;
        if (options.locationKey() == null || options.locationKey().isBlank()) {
            if (locations.size() != 1) throw new IllegalArgumentException(
                "Expected one identifier location, found " + locations.size() + "; choose one with --id-location: "
                    + locations.stream().map(IdentifierLocation::key).toList());
            location = locations.get(0);
        } else location = locations.stream().filter(item -> item.key().equals(options.locationKey())).findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Identifier location not found: " + options.locationKey()));

        HttpRequestData targetRequest = location.replace(request, target);
        List<PlannedRequest> output = new ArrayList<>();
        output.add(PlannedRequest.baseline(request, "idor.baseline.control"));
        output.add(PlannedRequest.baseline(targetRequest, "idor.baseline.target"));
        if (options.maxMutations() == 0) return complete(output, options);
        List<PairedControlSeparatorPlanner.Candidate> separatorCandidates = selectedFamilies.contains(
            PairedControlSeparatorPlanner.FAMILY)
            ? new PairedControlSeparatorPlanner().inventory(request, location, authorized, target).candidates()
            : List.of();
        for (var candidate : separatorCandidates) {
            if (!candidate.priority()) continue;
            output.add(new PlannedRequest(PairedControlSeparatorPlanner.FAMILY, candidate.label(),
                candidate.encoding(), candidate.apply(request, location), false));
            if (output.size() - 2 >= options.maxMutations()) return complete(output, options);
        }
        List<PairedControlSeparatorPlanner.Candidate> separatorRemainder = separatorCandidates.stream()
            .filter(candidate -> !candidate.priority()).toList();
        if (location.kind() == IdentifierLocation.Kind.HEADER
            || location.kind() == IdentifierLocation.Kind.COOKIE
            || location.kind() == IdentifierLocation.Kind.TEXT
            || location.kind() == IdentifierLocation.Kind.XML_TEXT
            || location.kind() == IdentifierLocation.Kind.XML_ATTRIBUTE
            || location.kind() == IdentifierLocation.Kind.MULTIPART) {
            for (var candidate : separatorRemainder) {
                output.add(new PlannedRequest(PairedControlSeparatorPlanner.FAMILY, candidate.label(),
                    candidate.encoding(), candidate.apply(request, location), false));
                if (output.size() - 2 >= options.maxMutations()) break;
            }
            return complete(output, options);
        }
        Map<String, List<HttpRequestData>> variants = new LinkedHashMap<>();
        boolean path = location.kind() == IdentifierLocation.Kind.PATH;
        boolean json = location.kind() == IdentifierLocation.Kind.JSON;
        variants.put("idor.path.suffix_formats", replacements(request, location, List.of(target + ".json", target + ".xml", target + ";", target + "/")));
        variants.put("idor.path.trailing_slash", path ? List.of(targetRequest.withRawTarget(toggleSlash(targetRequest.rawTarget()))) : List.of());
        variants.put(SPECIAL_IDENTIFIER_VALUES_FAMILY, replacements(request, location, List.of("0", "-1", "1", "null", "undefined", "*")));
        variants.put("idor.path.dot_segments", replacements(request, location,
            List.of(authorized + "/../" + target, authorized + "/%2e%2e/" + target,
                authorized + "%2f..%2f" + target, target + "/../" + authorized,
                "./" + target, "../" + target, "%2e/" + target)));
        variants.put("idor.query.conflicting_identifiers", queryVariants(targetRequest, authorized));
        variants.put("idor.query.parameter_pollution", pollution(targetRequest, location, authorized, target));
        variants.put("idor.query.comma_separated_identifiers", replacements(request, location, List.of(authorized + "," + target, target + "," + authorized)));
        variants.put("idor.query.json_wrap", location.kind() == IdentifierLocation.Kind.QUERY
            ? replacements(request, location, List.of("[\"" + target + "\"]", "{\"id\":\"" + target + "\"}")) : List.of());
        variants.put("idor.query.identifier_aliases", aliasQuery(targetRequest, target));
        variants.put(NUMERIC_PIVOTS_FAMILY, numeric(request, location, target));
        variants.put("idor.body.content_type_tampering", json ? List.of(targetRequest.upsertHeader("Content-Type", "text/plain"), targetRequest.upsertHeader("Content-Type", "application/x-www-form-urlencoded")) : List.of());
        variants.put("idor.body.json_wrap", json ? jsonReplacements(targetRequest, location, List.of("[\"" + target + "\"]", "{\"value\":\"" + target + "\"}")) : List.of());
        variants.put("idor.body.deserialization_hints", json ? List.of(targetRequest.addHeader("X-Type", "java.lang.String"), targetRequest.addHeader("X-Object-Type", "User")) : List.of());
        variants.put("idor.body.json_batch_identifiers", json ? jsonReplacements(targetRequest, location, List.of("[\"" + authorized + "\",\"" + target + "\"]")) : List.of());
        variants.put("idor.body.json_parameter_pollution", json && !location.path().matches(".*/\\d+")
            ? List.of(JsonSlotMutation.duplicateKey(targetRequest, location.path(), authorized, target),
                JsonSlotMutation.duplicateKey(targetRequest, location.path(), target, authorized))
            : List.of());
        variants.put(JSON_EDGE_CASES_FAMILY, json ? jsonReplacements(targetRequest, location, List.of("null", "0", "-1", "1e0")) : List.of());
        variants.put("idor.body.wildcard_identifiers", json ? replacements(request, location, List.of("*", "%", "_")) : List.of());
        variants.put("idor.body.unexpected_data_types", json ? jsonReplacements(targetRequest, location, List.of("true", "false", "[]", "{}")) : List.of());
        variants.put("idor.hybrid.trailing_control_characters", replacements(request, location, List.of(target + "%00", target + "%0a", target + "%09")));
        variants.put("idor.hybrid.empty_identifier_values", replacements(request, location, List.of("", "null", "undefined")));
        variants.put("idor.hybrid.resource_shortcuts", replacements(request, location, List.of("me", "self", "current")));
        variants.put("idor.hybrid.case_variants", replacements(request, location, List.of(target.toUpperCase(Locale.ROOT), target.toLowerCase(Locale.ROOT))));
        variants.put(CANONICAL_IDENTIFIER_FORMATS_FAMILY, canonical(request, location, target));
        variants.put("idor.hybrid.uuid_neighbor_edits", uuidNeighbors(request, location, target));
        variants.put(TRUNCATED_IDENTIFIER_VARIANTS_FAMILY, truncated(request, location, target));
        variants.put("idor.hybrid.uuid_version_variants", uuidVersions(request, location, target));
        variants.put("idor.hybrid.accept_negotiation", List.of(targetRequest.upsertHeader("Accept", "application/json"), targetRequest.upsertHeader("Accept", "text/plain"), targetRequest.upsertHeader("Accept", "*/*")));
        variants.put("idor.hybrid.cross_source_conflicts", List.of(targetRequest.addHeader("X-User-Id", authorized), targetRequest.addHeader("X-Object-Id", target)));
        variants.put("idor.hybrid.query_body_cross_source", location.kind() == IdentifierLocation.Kind.QUERY || json
            ? List.of(targetRequest.withRawTarget(appendQuery(targetRequest.rawTarget(), "id=" + authorized))) : List.of());
        variants.put("idor.hybrid.identifier_encoding", replacements(request, location,
            List.of(percentEncode(target), percentEncode(percentEncode(target)))));
        variants.put("idor.hybrid.method_override", options.includeMethodChanges()
            ? List.of(targetRequest.withMethod("GET"), targetRequest.withMethod("HEAD"),
                targetRequest.withMethod("PUT"), targetRequest.withMethod("PATCH"),
                targetRequest.upsertHeader("X-HTTP-Method-Override", "GET"),
                targetRequest.upsertHeader("X-HTTP-Method-Override", "PUT")) : List.of());

        int row = 0;
        Set<String> seen = new LinkedHashSet<>(List.of(request.toRaw(), targetRequest.toRaw()));
        boolean added;
        do {
            added = false;
            if (row < separatorRemainder.size()) {
                var candidate = separatorRemainder.get(row);
                output.add(new PlannedRequest(PairedControlSeparatorPlanner.FAMILY, candidate.label(),
                    candidate.encoding(), candidate.apply(request, location), false));
                added = true;
                if (output.size() - 2 >= options.maxMutations()) return complete(output, options);
            }
            for (Map.Entry<String, List<HttpRequestData>> entry : variants.entrySet()) {
                if (!selectedFamilies.contains(entry.getKey())) continue;
                if (row >= entry.getValue().size()) continue;
                HttpRequestData mutation = entry.getValue().get(row);
                String key = mutation.toRaw();
                if (seen.add(key)) output.add(new PlannedRequest(entry.getKey(),
                    entry.getKey() + " #" + (row + 1), "", mutation, false));
                added = true;
                if (output.size() - 2 >= options.maxMutations()) return complete(output, options);
            }
            row++;
        } while (added);
        return complete(output, options);
    }

    private List<PlannedRequest> complete(List<PlannedRequest> output, IdorPlanOptions options) {
        if (options.uniqueJsonPointer() == null || options.uniqueJsonPointer().isBlank())
            return List.copyOf(output);
        List<PlannedRequest> unique = new ArrayList<>(output.size());
        for (int index = 0; index < output.size(); index++) {
            PlannedRequest item = output.get(index);
            unique.add(new PlannedRequest(item.family(), item.payload(), item.encoding(),
                JsonSlotMutation.uniqueString(item.request(), options.uniqueJsonPointer(),
                    options.uniqueToken(), index + 1), item.baseline()));
        }
        return List.copyOf(unique);
    }

    private List<HttpRequestData> replacements(HttpRequestData request, IdentifierLocation location, List<String> values) { return values.stream().map(value -> location.replace(request, value)).toList(); }
    private List<HttpRequestData> jsonReplacements(HttpRequestData request, IdentifierLocation location, List<String> rawValues) {
        return rawValues.stream().map(raw -> JsonSlotMutation.replace(request, location.path(), raw)).toList();
    }
    private List<HttpRequestData> queryVariants(HttpRequestData request, String other) { return List.of(request.withRawTarget(appendQuery(request.rawTarget(), "id=" + queryEncode(other))), request.withRawTarget(appendQuery(request.rawTarget(), "userId=" + queryEncode(other)))); }
    private List<HttpRequestData> pollution(HttpRequestData request, IdentifierLocation location,
                                             String authorized, String target) {
        String name = location.kind() == IdentifierLocation.Kind.QUERY ? location.path() : "id";
        String key = queryEncode(name);
        String auth = queryEncode(authorized), other = queryEncode(target);
        return List.of(
            request.withRawTarget(appendQuery(request.rawTarget(), key + "=" + auth)),
            request.withRawTarget(appendQuery(appendQuery(request.rawTarget(), key + "=" + auth), key + "=" + other)),
            request.withRawTarget(appendQuery(appendQuery(request.rawTarget(), key + "=" + other), key + "=" + auth)),
            request.withRawTarget(appendQuery(request.rawTarget(), key + "%5B%5D=" + auth)),
            request.withRawTarget(appendQuery(request.rawTarget(), key + "%5B%5D=" + other)));
    }
    private List<HttpRequestData> aliasQuery(HttpRequestData request, String target) { return List.of("id", "user_id", "userId", "objectId", "accountId").stream().map(name -> request.withRawTarget(appendQuery(request.rawTarget(), name + "=" + queryEncode(target)))).toList(); }
    private List<HttpRequestData> numeric(HttpRequestData request, IdentifierLocation location, String target) { try { long value = Long.parseLong(target); return replacements(request, location, List.of(String.valueOf(value - 1), String.valueOf(value + 1), String.valueOf(value + 10))); } catch (NumberFormatException ignored) { return List.of(); } }
    private List<HttpRequestData> canonical(HttpRequestData request, IdentifierLocation location, String target) { return replacements(request, location, List.of(target.replace("-", ""), target.startsWith("0") ? target.replaceFirst("^0+", "") : "0" + target)); }
    private List<HttpRequestData> uuidNeighbors(HttpRequestData request, IdentifierLocation location, String target) { try { UUID uuid = UUID.fromString(target); String value = uuid.toString(); char last = value.charAt(value.length() - 1); char next = Character.forDigit((Character.digit(last, 16) + 1) & 15, 16); return replacements(request, location, List.of(value.substring(0, value.length() - 1) + next)); } catch (Exception ignored) { return List.of(); } }
    private List<HttpRequestData> truncated(HttpRequestData request, IdentifierLocation location, String target) { List<String> values = new ArrayList<>(); for (int size : List.of(1, 2, 4, 8)) if (target.length() > size) values.add(target.substring(0, target.length() - size)); return replacements(request, location, values); }
    private List<HttpRequestData> uuidVersions(HttpRequestData request, IdentifierLocation location, String target) { try { UUID.fromString(target); List<String> values = new ArrayList<>(); for (char version : List.of('1', '3', '4', '5')) { StringBuilder value = new StringBuilder(target.toLowerCase(Locale.ROOT)); value.setCharAt(14, version); values.add(value.toString()); } return replacements(request, location, values); } catch (Exception ignored) { return List.of(); } }
    private String toggleSlash(String target) { int query = target.indexOf('?'); String path = query < 0 ? target : target.substring(0, query); String suffix = query < 0 ? "" : target.substring(query); return (path.endsWith("/") ? path.substring(0, path.length() - 1) : path + "/") + suffix; }
    private String appendQuery(String target, String pair) { return target + (target.contains("?") ? "&" : "?") + pair; }
    private String queryEncode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private String percentEncode(String value) {
        StringBuilder encoded = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) encoded.append(String.format("%%%02X", b & 255));
        return encoded.toString();
    }
}
