package com.bypassfuzzer.core.scan;

import com.bypassfuzzer.core.http.HttpRequestData;
import com.bypassfuzzer.core.http.HttpHeader;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** An exact identifier slot in a request. Indices are zero-based. */
public record IdentifierLocation(Kind kind, int index, String path,
                                 int byteOffset, int byteLength, String charsetName) {
    public enum Kind { PATH, QUERY, FORM, JSON, HEADER, COOKIE, TEXT, XML_TEXT, XML_ATTRIBUTE, MULTIPART }

    public IdentifierLocation(Kind kind, int index, String path) {
        this(kind, index, path, -1, -1, "UTF-8");
    }

    public String key() {
        return switch (kind) {
            case PATH -> "path:" + index;
            case QUERY -> "query:" + path + "#" + index;
            case FORM -> "form:" + path + "#" + index;
            case JSON -> "json:" + path;
            case HEADER -> "header:" + path + "#" + index;
            case COOKIE -> "cookie:" + path + "#" + index;
            case TEXT -> "text:#" + index;
            case XML_TEXT -> "xml:text#" + index;
            case XML_ATTRIBUTE -> "xml:attribute:" + path + "#" + index;
            case MULTIPART -> "multipart:" + path + "#" + index;
        };
    }

    public static List<IdentifierLocation> discover(HttpRequestData request, String value) {
        if (value == null || value.isEmpty()) return List.of();
        List<IdentifierLocation> found = new ArrayList<>();
        String[] path = request.path().split("/", -1);
        for (int i = 0; i < path.length; i++) {
            if (path[i].equals(value)) found.add(new IdentifierLocation(Kind.PATH, i, ""));
        }
        discoverPairs(request.query(), value, Kind.QUERY, found);
        discoverHeaders(request, value, found);
        String body = new String(request.body(), StandardCharsets.UTF_8);
        String type = request.firstHeader("Content-Type").orElse("").toLowerCase();
        if (type.contains("application/x-www-form-urlencoded")) discoverPairs(body, value, Kind.FORM, found);
        if (type.contains("json")) {
            try { discoverJson(JsonParser.parseString(body), "", value, found); }
            catch (RuntimeException ignored) { /* Invalid JSON is not a selectable JSON field. */ }
        }
        if (type.contains("xml")) found.addAll(IdentifierBodySlots.xml(request, value));
        if (type.contains("multipart/form-data")) found.addAll(IdentifierBodySlots.multipart(request, value));
        if (type.startsWith("text/plain")) found.addAll(IdentifierBodySlots.text(request, value));
        return List.copyOf(found);
    }

    private static void discoverHeaders(HttpRequestData request, String value, List<IdentifierLocation> found) {
        Map<String, Integer> headerCounts = new HashMap<>();
        Map<String, Integer> cookieCounts = new HashMap<>();
        int rawOffset = request.method().length() + 1 + request.rawTarget().length() + 11;
        for (HttpHeader header : request.headers()) {
            String name = header.name().toLowerCase(java.util.Locale.ROOT);
            int headerIndex = headerCounts.merge(name, 1, Integer::sum) - 1;
            if (header.value().equals(value) && !excludedHeader(name))
                found.add(new IdentifierLocation(Kind.HEADER, headerIndex, name,
                    rawOffset + header.name().length() + 2, value.length(), "ISO-8859-1"));
            if (name.equals("cookie")) {
                int partOffset = 0;
                for (String part : header.value().split(";", -1)) {
                    int equals = part.indexOf('=');
                    if (equals > 0) {
                        String cookieName = part.substring(0, equals).trim();
                        String cookieValue = part.substring(equals + 1).trim();
                        String lower = cookieName.toLowerCase(java.util.Locale.ROOT);
                        int ordinal = cookieCounts.merge(lower, 1, Integer::sum) - 1;
                        if (cookieValue.equals(value) && !credentialName(lower)) {
                            int valueStart = part.indexOf(cookieValue, equals + 1);
                            found.add(new IdentifierLocation(Kind.COOKIE, ordinal, lower,
                                rawOffset + header.name().length() + 2 + partOffset + valueStart,
                                value.length(), "ISO-8859-1"));
                        }
                    }
                    partOffset += part.length() + 1;
                }
            }
            rawOffset += header.name().length() + 2 + header.value().length() + 2;
        }
    }

    private static boolean excludedHeader(String name) {
        return name.equals("host") || name.equals("cookie") || name.equals("authorization")
            || name.equals("proxy-authorization") || name.equals("content-length")
            || name.equals("transfer-encoding") || name.equals("connection")
            || name.equals("upgrade") || name.equals("te") || name.equals("trailer")
            || name.equals("expect") || credentialName(name);
    }

    private static boolean credentialName(String name) {
        return name.contains("auth") || name.contains("token") || name.contains("secret")
            || name.contains("session") || name.contains("csrf") || name.contains("xsrf")
            || name.contains("jwt") || name.contains("api-key") || name.contains("api_key")
            || name.equals("sid") || name.endsWith("_sid") || name.endsWith("-sid");
    }

    private static void discoverPairs(String raw, String value, Kind kind, List<IdentifierLocation> found) {
        if (raw == null || raw.isEmpty()) return;
        String[] pairs = raw.split("&", -1);
        for (int i = 0; i < pairs.length; i++) {
            int equal = pairs[i].indexOf('=');
            String name = equal < 0 ? pairs[i] : pairs[i].substring(0, equal);
            String rawValue = equal < 0 ? "" : pairs[i].substring(equal + 1);
            if (decode(rawValue).equals(value)) found.add(new IdentifierLocation(kind, i, decode(name)));
        }
    }

    private static void discoverJson(JsonElement element, String pointer, String value, List<IdentifierLocation> found) {
        if (element.isJsonObject()) {
            for (Map.Entry<String, JsonElement> field : element.getAsJsonObject().entrySet())
                discoverJson(field.getValue(), pointer + "/" + escape(field.getKey()), value, found);
        } else if (element.isJsonArray()) {
            JsonArray array = element.getAsJsonArray();
            for (int i = 0; i < array.size(); i++) discoverJson(array.get(i), pointer + "/" + i, value, found);
        } else if (element.isJsonPrimitive() && element.getAsJsonPrimitive().getAsString().equals(value)) {
            found.add(new IdentifierLocation(Kind.JSON, 0, pointer));
        }
    }

    public HttpRequestData replace(HttpRequestData request, String replacement) {
        return switch (kind) {
            case PATH -> {
                String[] segments = request.path().split("/", -1);
                if (index < 0 || index >= segments.length) throw new IllegalArgumentException("Path location changed");
                segments[index] = replacement;
                String query = request.query();
                yield request.withRawTarget(String.join("/", segments) + (request.rawTarget().contains("?") ? "?" + query : ""));
            }
            case QUERY -> request.withRawTarget(request.path() + "?" + replacePair(request.query(), replacement));
            case FORM -> request.withBody(replacePair(new String(request.body(), StandardCharsets.UTF_8), replacement)
                .getBytes(StandardCharsets.UTF_8)).withSyncedContentLength();
            case JSON -> {
                JsonElement root = JsonParser.parseString(new String(request.body(), StandardCharsets.UTF_8));
                String[] tokens = path.substring(1).split("/", -1);
                JsonElement parent = root;
                for (int i = 0; i < tokens.length - 1; i++) parent = child(parent, unescape(tokens[i]));
                String last = unescape(tokens[tokens.length - 1]);
                JsonElement old = child(parent, last);
                JsonPrimitive next = old.isJsonPrimitive() && old.getAsJsonPrimitive().isNumber()
                    && replacement.matches("-?\\d+(?:\\.\\d+)?")
                    ? new JsonPrimitive(new java.math.BigDecimal(replacement)) : new JsonPrimitive(replacement);
                if (parent.isJsonObject()) parent.getAsJsonObject().add(last, next);
                else parent.getAsJsonArray().set(Integer.parseInt(last), next);
                yield request.withBody(root.toString().getBytes(StandardCharsets.UTF_8)).withSyncedContentLength();
            }
            case HEADER -> {
                List<HttpHeader> headers = new ArrayList<>(request.headers());
                int ordinal = 0;
                for (int i = 0; i < headers.size(); i++) {
                    HttpHeader header = headers.get(i);
                    if (!header.name().equalsIgnoreCase(path)) continue;
                    if (ordinal++ == index) {
                        headers.set(i, new HttpHeader(header.name(), replacement));
                        yield new HttpRequestData(request.origin(), request.method(), request.rawTarget(),
                            request.protocol(), headers, request.body());
                    }
                }
                throw new IllegalArgumentException("Header location changed");
            }
            case COOKIE -> replaceCookie(request, replacement);
            case TEXT, MULTIPART, XML_TEXT, XML_ATTRIBUTE -> replaceBodySpan(request, replacement);
        };
    }

    public boolean canEncode(HttpRequestData request, String value) {
        if (kind == Kind.XML_TEXT || kind == Kind.XML_ATTRIBUTE)
            value = xmlEncode(value, kind == Kind.XML_ATTRIBUTE);
        try { return Charset.forName(charsetName).newEncoder().canEncode(value); }
        catch (RuntimeException error) { return false; }
    }

    private HttpRequestData replaceBodySpan(HttpRequestData request, String replacement) {
        if (byteOffset < 0 || byteLength < 0 || byteOffset + byteLength > request.body().length)
            throw new IllegalArgumentException("Body location changed");
        String value = kind == Kind.XML_TEXT || kind == Kind.XML_ATTRIBUTE
            ? xmlEncode(replacement, kind == Kind.XML_ATTRIBUTE) : replacement;
        if (!canEncode(request, replacement)) throw new IllegalArgumentException("Unsupported body charset");
        byte[] encoded = value.getBytes(Charset.forName(charsetName));
        byte[] body = request.body();
        byte[] updated = new byte[body.length - byteLength + encoded.length];
        System.arraycopy(body, 0, updated, 0, byteOffset);
        System.arraycopy(encoded, 0, updated, byteOffset, encoded.length);
        System.arraycopy(body, byteOffset + byteLength, updated, byteOffset + encoded.length,
            body.length - byteOffset - byteLength);
        return request.withBody(updated).withSyncedContentLength();
    }

    private static String xmlEncode(String value, boolean attribute) {
        StringBuilder encoded = new StringBuilder();
        value.codePoints().forEach(cp -> {
            if (cp == '&') encoded.append("&amp;");
            else if (cp == '<') encoded.append("&lt;");
            else if (attribute && cp == '"') encoded.append("&quot;");
            else if (attribute && cp == '\'') encoded.append("&apos;");
            else if (Character.getType(cp) == Character.CONTROL
                || Character.getType(cp) == Character.FORMAT
                || cp == 0x2028 || cp == 0x2029)
                encoded.append("&#x").append(Integer.toHexString(cp).toUpperCase()).append(';');
            else encoded.appendCodePoint(cp);
        });
        return encoded.toString();
    }

    private HttpRequestData replaceCookie(HttpRequestData request, String replacement) {
        List<HttpHeader> headers = new ArrayList<>(request.headers());
        int ordinal = 0;
        for (int i = 0; i < headers.size(); i++) {
            HttpHeader header = headers.get(i);
            if (!header.name().equalsIgnoreCase("Cookie")) continue;
            String[] parts = header.value().split(";", -1);
            for (int j = 0; j < parts.length; j++) {
                int equal = parts[j].indexOf('=');
                if (equal < 0 || !parts[j].substring(0, equal).trim().equalsIgnoreCase(path)) continue;
                if (ordinal++ == index) {
                    String left = parts[j].substring(0, equal + 1);
                    String rest = parts[j].substring(equal + 1);
                    int leading = 0, trailing = rest.length();
                    while (leading < rest.length() && Character.isWhitespace(rest.charAt(leading))) leading++;
                    while (trailing > leading && Character.isWhitespace(rest.charAt(trailing - 1))) trailing--;
                    parts[j] = left + rest.substring(0, leading) + replacement + rest.substring(trailing);
                    headers.set(i, new HttpHeader(header.name(), String.join(";", parts)));
                    return new HttpRequestData(request.origin(), request.method(), request.rawTarget(),
                        request.protocol(), headers, request.body());
                }
            }
        }
        throw new IllegalArgumentException("Cookie location changed");
    }

    private String replacePair(String raw, String replacement) {
        String[] pairs = raw.split("&", -1);
        if (index < 0 || index >= pairs.length) throw new IllegalArgumentException("Parameter location changed");
        String name = pairs[index].split("=", 2)[0];
        pairs[index] = name + "=" + URLEncoder.encode(replacement, StandardCharsets.UTF_8);
        return String.join("&", pairs);
    }

    private static JsonElement child(JsonElement parent, String token) {
        return parent.isJsonObject() ? parent.getAsJsonObject().get(token) : parent.getAsJsonArray().get(Integer.parseInt(token));
    }
    private static String decode(String value) { return URLDecoder.decode(value, StandardCharsets.UTF_8); }
    private static String escape(String value) { return value.replace("~", "~0").replace("/", "~1"); }
    private static String unescape(String value) { return value.replace("~1", "/").replace("~0", "~"); }
}
