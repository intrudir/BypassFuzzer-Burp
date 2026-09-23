package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpResponseData;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Response-derived JSON body probes shared by the Burp and CLI IDOR surfaces. */
public final class ResponseGuidedIdorPlanner {
    public static final String FAMILY = "idor.body.response_guided_mass_assignment";
    private static final int MAX_RESPONSE_BYTES = 1_048_576;
    private static final int MAX_DEPTH = 32;
    private static final int MAX_FIELDS = 64;

    public record PathPart(String token, boolean arrayIndex) { }
    public record ResponseField(String pointer, boolean numeric, String baseline, String value,
                                List<PathPart> parts) {
        public ResponseField { parts = List.copyOf(parts); }
    }

    public boolean enabled(IdorPlanOptions options) {
        return options.families().isEmpty() || options.families().contains(FAMILY);
    }

    /** Static controls are sent before any response-derived planning. */
    public List<PlannedRequest> initialPlan(HttpRequestData request, IdorPlanOptions options) {
        return plan(request, options, null, null).subList(0, 2);
    }

    /** Returns the complete preview/execution plan; live baseline responses are authoritative. */
    public List<PlannedRequest> plan(HttpRequestData request, IdorPlanOptions options,
                                     HttpResponseData authorized, HttpResponseData target) {
        List<PlannedRequest> staticPlan = new IdorPlanner().plan(request,
            withoutUnique(options, IdorPlanOptions.UNLIMITED));
        List<PlannedRequest> dynamic = enabled(options) ? probes(request, options, authorized, target) : List.of();
        List<PlannedRequest> combined = new ArrayList<>(staticPlan.subList(0, 2));
        int staticIndex = 2, dynamicIndex = 0;
        while (combined.size() - 2 < options.maxMutations()
            && (staticIndex < staticPlan.size() || dynamicIndex < dynamic.size())) {
            if (staticIndex < staticPlan.size()) combined.add(staticPlan.get(staticIndex++));
            if (combined.size() - 2 >= options.maxMutations()) break;
            if (dynamicIndex < dynamic.size()) combined.add(dynamic.get(dynamicIndex++));
        }
        String pointer = effectiveUniquePointer(request, options);
        if (pointer == null) return List.copyOf(combined);
        List<PlannedRequest> unique = new ArrayList<>(combined.size());
        for (int index = 0; index < combined.size(); index++) {
            PlannedRequest item = combined.get(index);
            String current = requestStringAt(item.request(), pointer);
            HttpRequestData updated = options.authorizedId().equals(current)
                || options.targetId().equals(current) ? item.request()
                : JsonSlotMutation.uniqueString(item.request(), pointer, options.uniqueToken(), index + 1);
            unique.add(new PlannedRequest(item.family(), item.payload(), item.encoding(),
                updated,
                item.baseline(), item.intent(), item.sourcePointer(), item.targetIdentifier()));
        }
        return List.copyOf(unique);
    }

    public List<ResponseField> discover(HttpResponseData authorized, HttpResponseData target,
                                         String authorizedId, String targetId) {
        Map<String, ResponseField> found = new LinkedHashMap<>();
        discoverOne(authorized, "authorized", authorizedId, targetId, found);
        discoverOne(target, "target", authorizedId, targetId, found);
        return List.copyOf(found.values());
    }

    /** Exact response value at a JSON pointer, or null when absent/non-scalar. */
    public static String valueAt(HttpResponseData response, String pointer) {
        if (response == null || response.body().length > MAX_RESPONSE_BYTES
            || pointer == null || !pointer.startsWith("/")) return null;
        try {
            JsonElement node = JsonParser.parseString(new String(response.body(), StandardCharsets.UTF_8));
            for (String token : pointer.substring(1).split("/", -1)) {
                String key = token.replace("~1", "/").replace("~0", "~");
                if (node.isJsonObject()) node = node.getAsJsonObject().get(key);
                else if (node.isJsonArray()) node = node.getAsJsonArray().get(Integer.parseInt(key));
                else return null;
                if (node == null) return null;
            }
            return node.isJsonPrimitive() ? node.getAsString() : null;
        } catch (RuntimeException invalid) { return null; }
    }

    private void discoverOne(HttpResponseData response, String source, String a, String b,
                             Map<String, ResponseField> found) {
        if (response == null || response.body().length > MAX_RESPONSE_BYTES) return;
        try {
            JsonElement root = JsonParser.parseString(new String(response.body(), StandardCharsets.UTF_8));
            collect(root, new ArrayList<>(), source, a, b, found, 0);
        } catch (RuntimeException ignored) { /* Non-JSON baseline has no JSON fields. */ }
    }

    private void collect(JsonElement node, List<PathPart> path, String source, String a, String b,
                         Map<String, ResponseField> found, int depth) {
        if (depth > MAX_DEPTH || found.size() >= MAX_FIELDS || node == null || node.isJsonNull()) return;
        if (node.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : node.getAsJsonObject().entrySet()) {
                path.add(new PathPart(entry.getKey(), false));
                collect(entry.getValue(), path, source, a, b, found, depth + 1);
                path.remove(path.size() - 1);
            }
        } else if (node.isJsonArray()) {
            JsonArray array = node.getAsJsonArray();
            for (int index = 0; index < array.size(); index++) {
                path.add(new PathPart(String.valueOf(index), true));
                collect(array.get(index), path, source, a, b, found, depth + 1);
                path.remove(path.size() - 1);
            }
        } else if (node.isJsonPrimitive() && !path.isEmpty()) {
            JsonPrimitive value = node.getAsJsonPrimitive();
            if (!value.isString() && !value.isNumber()) return;
            String scalar = value.getAsString();
            if (!(a != null && !a.isEmpty() && scalar.equals(a))
                && !(b != null && !b.isEmpty() && scalar.equals(b))) return;
            String pointer = path.stream().map(part -> "/" + part.token().replace("~", "~0").replace("/", "~1"))
                .reduce("", String::concat);
            found.putIfAbsent(pointer, new ResponseField(pointer, value.isNumber(), source, scalar, path));
        }
    }

    private List<PlannedRequest> probes(HttpRequestData request, IdorPlanOptions options,
                                         HttpResponseData authorized, HttpResponseData target) {
        try { JsonParser.parseString(new String(request.body(), StandardCharsets.UTF_8)).getAsJsonObject(); }
        catch (RuntimeException invalid) { return List.of(); }
        List<ResponseField> fields = discover(authorized, target, options.authorizedId(), options.targetId());
        if (fields.isEmpty()) return List.of();
        IdentifierLocation slot = IdentifierLocation.discover(request, options.authorizedId()).stream()
            .filter(location -> location.key().equals(options.locationKey())).findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Identifier location not found: " + options.locationKey()));
        HttpRequestData targetRequest = slot.replace(request, options.targetId());
        List<PlannedRequest> exact = new ArrayList<>(), inferred = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>(List.of(request.toRaw(), targetRequest.toRaw()));
        for (ResponseField field : fields) {
            for (Shape shape : shapes(field)) {
                for (ProbeIntent intent : List.of(ProbeIntent.MASS_ASSIGNMENT, ProbeIntent.PATH_BODY_CONFLICT)) {
                    HttpRequestData base = intent == ProbeIntent.MASS_ASSIGNMENT ? request : targetRequest;
                    String injected = intent == ProbeIntent.MASS_ASSIGNMENT ? options.targetId() : options.authorizedId();
                    JsonElement value = field.numeric() && injected.matches("-?\\d+(?:\\.\\d+)?")
                        ? new JsonPrimitive(new java.math.BigDecimal(injected)) : new JsonPrimitive(injected);
                    HttpRequestData mutation = insert(base, shape.parts(), value);
                    if (mutation == null || !seen.add(mutation.toRaw())) continue;
                    String direction = intent == ProbeIntent.MASS_ASSIGNMENT ? "authorized path / target body" : "target path / authorized body";
                    PlannedRequest planned = new PlannedRequest(FAMILY,
                        direction + " | " + field.pointer() + " | " + shape.label(),
                        shape.label(), mutation, false, intent, field.pointer(), options.targetId());
                    (shape.exact() ? exact : inferred).add(planned);
                }
            }
        }
        exact.addAll(inferred);
        return exact;
    }

    private List<Shape> shapes(ResponseField field) {
        List<Shape> output = new ArrayList<>();
        List<PathPart> normalized = field.parts().stream()
            .map(part -> part.arrayIndex() ? new PathPart("0", true) : part).toList();
        output.add(new Shape("exact", normalized, true));
        String leaf = field.parts().get(field.parts().size() - 1).token();
        String parent = "";
        for (int index = field.parts().size() - 2; index >= 0; index--)
            if (!field.parts().get(index).arrayIndex()) { parent = field.parts().get(index).token(); break; }
        LinkedHashSet<String> aliases = new LinkedHashSet<>();
        aliases.add(snake(leaf)); aliases.add(camel(leaf));
        if (!parent.isEmpty()) {
            String stem = singular(parent);
            aliases.add(snake(stem + "_" + leaf));
            aliases.add(camel(stem + "_" + leaf));
        }
        for (String alias : aliases) {
            if (field.parts().size() == 1 && alias.equals(leaf)) continue;
            output.add(new Shape("alias " + alias, List.of(new PathPart(alias, false)), false));
        }
        String idStem = leaf.endsWith("_id") ? leaf.substring(0, leaf.length() - 3)
            : leaf.endsWith("Id") ? leaf.substring(0, leaf.length() - 2)
            : leaf.equalsIgnoreCase("id") ? singular(parent) : "";
        if (!idStem.isBlank()) {
            output.add(new Shape("object " + idStem, List.of(new PathPart(idStem, false),
                new PathPart("id", false)), false));
            output.add(new Shape("array " + idStem, List.of(new PathPart(idStem + "s", false),
                new PathPart("0", true)), false));
        }
        return output;
    }

    private HttpRequestData insert(HttpRequestData base, List<PathPart> path, JsonElement value) {
        JsonObject root = JsonParser.parseString(new String(base.body(), StandardCharsets.UTF_8))
            .getAsJsonObject();
        JsonElement current = root;
        for (int index = 0; index < path.size(); index++) {
            PathPart part = path.get(index);
            boolean leaf = index == path.size() - 1;
            if (!part.arrayIndex()) {
                if (!current.isJsonObject()) return null;
                JsonObject object = current.getAsJsonObject();
                if (leaf) object.add(part.token(), value);
                else {
                    JsonElement child = object.get(part.token());
                    if (child == null || child.isJsonNull()) {
                        child = path.get(index + 1).arrayIndex() ? new JsonArray() : new JsonObject();
                        object.add(part.token(), child);
                    }
                    current = child;
                }
            } else {
                if (!current.isJsonArray()) return null;
                JsonArray array = current.getAsJsonArray();
                if (array.size() == 0) array.add(leaf ? value
                    : path.get(index + 1).arrayIndex() ? new JsonArray() : new JsonObject());
                else if (leaf) array.set(0, value);
                if (!leaf) current = array.get(0);
            }
        }
        return base.withBody(root.toString().getBytes(StandardCharsets.UTF_8)).withSyncedContentLength();
    }

    private String effectiveUniquePointer(HttpRequestData request, IdorPlanOptions options) {
        if (options.uniqueJsonPointer() != null && !options.uniqueJsonPointer().isBlank())
            return options.uniqueJsonPointer();
        if (!enabled(options) || options.uniqueToken() == null || options.uniqueToken().isBlank()) return null;
        if (!Set.of("POST", "PUT", "PATCH").contains(request.method().toUpperCase(Locale.ROOT))) return null;
        try {
            JsonElement name = JsonParser.parseString(new String(request.body(), StandardCharsets.UTF_8))
                .getAsJsonObject().get("name");
            return name != null && name.isJsonPrimitive() && name.getAsJsonPrimitive().isString() ? "/name" : null;
        } catch (RuntimeException invalid) { return null; }
    }

    private String requestStringAt(HttpRequestData request, String pointer) {
        if (pointer == null || !pointer.startsWith("/")) return null;
        try {
            JsonElement node = JsonParser.parseString(new String(request.body(), StandardCharsets.UTF_8));
            for (String token : pointer.substring(1).split("/", -1)) {
                String key = token.replace("~1", "/").replace("~0", "~");
                node = node.isJsonObject() ? node.getAsJsonObject().get(key)
                    : node.isJsonArray() ? node.getAsJsonArray().get(Integer.parseInt(key)) : null;
                if (node == null) return null;
            }
            return node.isJsonPrimitive() && node.getAsJsonPrimitive().isString() ? node.getAsString() : null;
        } catch (RuntimeException invalid) { return null; }
    }

    private IdorPlanOptions withoutUnique(IdorPlanOptions options, int maximum) {
        return new IdorPlanOptions(options.authorizedId(), options.targetId(), options.locationKey(),
            options.families(), maximum, options.includeMethodChanges());
    }

    private String singular(String word) {
        if (word.endsWith("ies") && word.length() > 4) return word.substring(0, word.length() - 3) + "y";
        return word.endsWith("s") && word.length() > 3 ? word.substring(0, word.length() - 1) : word;
    }
    private String snake(String value) {
        return value.replaceAll("([a-z0-9])([A-Z])", "$1_$2").replace('-', '_').toLowerCase(Locale.ROOT);
    }
    private String camel(String value) {
        String[] words = snake(value).split("_+");
        StringBuilder output = new StringBuilder(words[0]);
        for (int index = 1; index < words.length; index++)
            if (!words[index].isEmpty()) output.append(Character.toUpperCase(words[index].charAt(0)))
                .append(words[index].substring(1));
        return output.toString();
    }

    private record Shape(String label, List<PathPart> parts, boolean exact) { }
}
