package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpRequestData;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import java.nio.charset.StandardCharsets;
import java.util.Map;

final class JsonSlotMutation {
    private JsonSlotMutation() { }

    static HttpRequestData replace(HttpRequestData request, String pointer, String rawJson) {
        JsonElement root = JsonParser.parseString(new String(request.body(), StandardCharsets.UTF_8));
        String[] tokens = pointer.substring(1).split("/", -1);
        JsonElement parent = root;
        for (int i = 0; i < tokens.length - 1; i++) parent = child(parent, decode(tokens[i]));
        String key = decode(tokens[tokens.length - 1]);
        JsonElement value = JsonParser.parseString(rawJson);
        if (parent.isJsonObject()) parent.getAsJsonObject().add(key, value);
        else parent.getAsJsonArray().set(Integer.parseInt(key), value);
        return request.withBody(root.toString().getBytes(StandardCharsets.UTF_8)).withSyncedContentLength();
    }

    static HttpRequestData uniqueString(HttpRequestData request, String pointer, String token, int index) {
        if (pointer == null || !pointer.startsWith("/") || pointer.length() == 1)
            throw new IllegalArgumentException("Unique JSON field must be a JSON pointer such as /name");
        try {
            JsonElement root = JsonParser.parseString(new String(request.body(), StandardCharsets.UTF_8));
            String[] tokens = pointer.substring(1).split("/", -1);
            JsonElement parent = root;
            for (int i = 0; i < tokens.length - 1; i++) parent = child(parent, decode(tokens[i]));
            String key = decode(tokens[tokens.length - 1]);
            JsonElement old = child(parent, key);
            if (old == null || !old.isJsonPrimitive() || !old.getAsJsonPrimitive().isString())
                throw new IllegalArgumentException("Unique JSON field must point to an existing string: " + pointer);
            JsonPrimitive next = new JsonPrimitive(old.getAsString() + "-bf-" + token + "-" + index);
            if (parent.isJsonObject()) parent.getAsJsonObject().add(key, next);
            else parent.getAsJsonArray().set(Integer.parseInt(key), next);
            return request.withBody(root.toString().getBytes(StandardCharsets.UTF_8)).withSyncedContentLength();
        } catch (RuntimeException invalidPointer) {
            throw new IllegalArgumentException("Unique JSON field must point to an existing string: " + pointer,
                invalidPointer);
        }
    }

    static HttpRequestData duplicateKey(HttpRequestData request, String pointer,
                                        String first, String second) {
        if (pointer == null || !pointer.startsWith("/"))
            throw new IllegalArgumentException("A JSON field pointer is required");
        String[] tokens = pointer.substring(1).split("/", -1);
        JsonElement root = JsonParser.parseString(new String(request.body(), StandardCharsets.UTF_8));
        String body = renderDuplicate(root, tokens, 0, first, second);
        return request.withBody(body.getBytes(StandardCharsets.UTF_8)).withSyncedContentLength();
    }

    private static String renderDuplicate(JsonElement element, String[] tokens, int depth,
                                          String first, String second) {
        if (element.isJsonObject()) {
            JsonObject object = element.getAsJsonObject();
            String key = decode(tokens[depth]);
            if (!object.has(key)) throw new IllegalArgumentException("JSON field no longer exists");
            StringBuilder rendered = new StringBuilder("{");
            boolean comma = false;
            for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
                if (comma) rendered.append(',');
                comma = true;
                String name = new JsonPrimitive(entry.getKey()).toString();
                if (entry.getKey().equals(key) && depth == tokens.length - 1) {
                    rendered.append(name).append(':').append(scalar(entry.getValue(), first))
                        .append(',').append(name).append(':').append(scalar(entry.getValue(), second));
                } else {
                    rendered.append(name).append(':').append(entry.getKey().equals(key)
                        ? renderDuplicate(entry.getValue(), tokens, depth + 1, first, second)
                        : entry.getValue().toString());
                }
            }
            return rendered.append('}').toString();
        }
        if (element.isJsonArray()) {
            JsonArray array = element.getAsJsonArray();
            int selected = Integer.parseInt(tokens[depth]);
            if (selected < 0 || selected >= array.size() || depth == tokens.length - 1)
                throw new IllegalArgumentException("Duplicate JSON keys require an object field");
            StringBuilder rendered = new StringBuilder("[");
            for (int index = 0; index < array.size(); index++) {
                if (index > 0) rendered.append(',');
                rendered.append(index == selected
                    ? renderDuplicate(array.get(index), tokens, depth + 1, first, second)
                    : array.get(index).toString());
            }
            return rendered.append(']').toString();
        }
        throw new IllegalArgumentException("Duplicate JSON keys require an object field");
    }

    private static String scalar(JsonElement original, String value) {
        if (original.isJsonPrimitive() && original.getAsJsonPrimitive().isNumber()
            && value.matches("-?\\d+(?:\\.\\d+)?")) return value;
        return new JsonPrimitive(value).toString();
    }

    private static JsonElement child(JsonElement parent, String token) {
        return parent.isJsonObject() ? parent.getAsJsonObject().get(token) : parent.getAsJsonArray().get(Integer.parseInt(token));
    }
    private static String decode(String value) { return value.replace("~1", "/").replace("~0", "~"); }
}
