package com.bypassfuzzer.core.http;


import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shared request-parameter extraction and mutation support for attack strategies.
 */
public final class RequestParameterSupport {

    private static final Gson GSON = new GsonBuilder().serializeNulls().create();

    private RequestParameterSupport() {
    }

    public static boolean supportsBody(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method);
    }

    public static String extractUrlEncodedBody(HttpRequestData request) {
        String contentType = request.firstHeader("Content-Type").orElse(null);
        if (contentType == null || !contentType.contains("application/x-www-form-urlencoded")) {
            return null;
        }

        if (request.body() == null || request.bodyLength() == 0) {
            return null;
        }

        return new String(request.body(), StandardCharsets.UTF_8);
    }

    public static Map<String, String> extractCombinedParameters(HttpRequestData request) {
        Map<String, String> params = new LinkedHashMap<>(QueryStringUtils.parseDecoded(request.query()));

        String contentType = request.firstHeader("Content-Type").orElse(null);
        if (contentType != null && request.body() != null && request.bodyLength() > 0) {
            params.putAll(parseBodyParameters(new String(request.body(), StandardCharsets.UTF_8), contentType));
        }

        return params;
    }

    public static List<LocatedParameter> extractLocatedParameters(HttpRequestData request) {
        List<LocatedParameter> params = new ArrayList<>();
        Map<String, Integer> queryOccurrences = new LinkedHashMap<>();

        for (QueryStringUtils.QueryParameter parameter : QueryStringUtils.parseRawParameters(request.query())) {
            int occurrence = nextOccurrence(queryOccurrences, parameter.name());
            params.add(new LocatedParameter(
                parameter.name(),
                parameter.value(),
                ParameterLocation.QUERY,
                parameter.name(),
                occurrence
            ));
        }

        String contentType = request.firstHeader("Content-Type").orElse(null);
        if (contentType != null && request.body() != null && request.bodyLength() > 0) {
            params.addAll(parseBodyLocatedParameters(new String(request.body(), StandardCharsets.UTF_8), contentType));
        }

        return params;
    }

    public static HttpRequestData prepareForBodyFormat(HttpRequestData request, String method) {
        HttpRequestData preparedRequest = request.withMethod(method);
        if (request.query() == null || request.query().isEmpty()) {
            return preparedRequest;
        }
        return preparedRequest.withRawTarget(request.path());
    }

    public static HttpRequestData applyBodyFormat(HttpRequestData request, Map<String, String> params, RequestBodyFormat format) {
        return applyBodyFormat(request, toLocatedParameters(params), format);
    }

    public static HttpRequestData applyBodyFormat(HttpRequestData request, List<LocatedParameter> params, RequestBodyFormat format) {
        return switch (format) {
            case URL_ENCODED -> request
                .upsertHeader("Content-Type", "application/x-www-form-urlencoded")
                .withBodyText(renderUrlEncoded(params));
            case JSON -> request
                .upsertHeader("Content-Type", "application/json")
                .withBodyText(renderJson(params));
            case XML -> request
                .upsertHeader("Content-Type", "application/xml")
                .withBodyText(renderXml(params));
            case MULTIPART -> {
                String boundary = "----WebKitFormBoundary"
                    + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
                yield request
                    .upsertHeader("Content-Type", "multipart/form-data; boundary=" + boundary)
                    .withBodyText(renderMultipart(params, boundary));
            }
        };
    }

    public static HttpRequestData replaceParameterName(HttpRequestData request, LocatedParameter parameter, String newName) {
        if (parameter.location() == ParameterLocation.QUERY) {
            return request.withRawTarget(QueryStringUtils.replaceName(request.rawTarget(), parameter.name(), newName, parameter.occurrence()));
        }

        String contentType = request.firstHeader("Content-Type").orElse(null);
        if (contentType == null) {
            return request;
        }

        String body = new String(request.body(), StandardCharsets.UTF_8);
        String newBody = body;
        if (contentType.contains("application/x-www-form-urlencoded")) {
            newBody = replaceFormParameterName(body, parameter, newName);
        } else if (contentType.contains("application/json")) {
            newBody = replaceJsonParameterName(body, parameter, newName);
        } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
            newBody = replaceXmlParameterName(body, parameter, newName);
        } else if (contentType.contains("multipart/form-data")) {
            newBody = replaceMultipartParameterName(body, contentType, parameter, newName);
        }

        return request.withBodyText(newBody);
    }

    public static HttpRequestData replaceParameterValue(HttpRequestData request, LocatedParameter parameter, String newValue) {
        if (parameter.location() == ParameterLocation.QUERY) {
            return request.withRawTarget(QueryStringUtils.replaceValue(request.rawTarget(), parameter.name(), newValue, parameter.occurrence()));
        }

        String contentType = request.firstHeader("Content-Type").orElse(null);
        if (contentType == null) {
            return request;
        }

        String body = new String(request.body(), StandardCharsets.UTF_8);
        String newBody = body;
        if (contentType.contains("application/x-www-form-urlencoded")) {
            newBody = replaceFormParameterValue(body, parameter, newValue);
        } else if (contentType.contains("application/json")) {
            newBody = replaceJsonParameterValue(body, parameter, newValue);
        } else if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
            newBody = replaceXmlParameterValue(body, parameter, newValue);
        } else if (contentType.contains("multipart/form-data")) {
            newBody = replaceMultipartParameterValue(body, contentType, parameter, newValue);
        }

        return request.withBodyText(newBody);
    }

    public static HttpRequestData replaceJsonParameterValueWithJson(HttpRequestData request, LocatedParameter parameter, String rawJsonValue) {
        String contentType = request.firstHeader("Content-Type").orElse(null);
        if (contentType == null || !contentType.contains("application/json")) {
            return request;
        }

        String body = new String(request.body(), StandardCharsets.UTF_8);
        String newBody = replaceJsonParameterValueWithJson(body, parameter, rawJsonValue);
        return request.withBodyText(newBody);
    }

    public static HttpRequestData replaceJsonParameterValuePreservingRawJson(HttpRequestData request,
                                                                         LocatedParameter parameter,
                                                                         String rawJsonValue) {
        String contentType = request.firstHeader("Content-Type").orElse(null);
        if (contentType == null || !contentType.contains("application/json")) {
            return request;
        }

        String body = new String(request.body(), StandardCharsets.UTF_8);
        String newBody = replaceJsonParameterValuePreservingRawJson(body, parameter, rawJsonValue);
        return request.withBodyText(newBody);
    }

    public static HttpRequestData replaceJsonParameterWithDuplicateKeys(HttpRequestData request,
                                                                    LocatedParameter parameter,
                                                                    String firstRawJsonValue,
                                                                    String secondRawJsonValue) {
        String contentType = request.firstHeader("Content-Type").orElse(null);
        if (contentType == null || !contentType.contains("application/json")) {
            return request;
        }

        String body = new String(request.body(), StandardCharsets.UTF_8);
        String newBody = replaceJsonParameterWithDuplicateKeys(body, parameter, firstRawJsonValue, secondRawJsonValue);
        return request.withBodyText(newBody);
    }

    public static HttpRequestData moveQueryToBody(HttpRequestData request, String method) {
        String query = request.query();
        if (query == null || query.isEmpty()) {
            return request.withMethod(method);
        }

        return request
            .withMethod(method)
            .upsertHeader("Content-Type", "application/x-www-form-urlencoded")
            .withBodyText(query)
            .withRawTarget(request.path());
    }

    public static HttpRequestData moveBodyToQuery(HttpRequestData request, String method, String bodyParams) {
        return request
            .withMethod(method)
            .withRawTarget(RequestPathUtils.replaceQuery(request.rawTarget(), bodyParams))
            .withBodyText("");
    }

    public static HttpRequestData putParamsInBoth(HttpRequestData request, String method, String params) {
        return request
            .withMethod(method)
            .withRawTarget(RequestPathUtils.replaceQuery(request.path(), params))
            .upsertHeader("Content-Type", "application/x-www-form-urlencoded")
            .withBodyText(params);
    }

    public static Map<String, String> parseBodyParameters(String body, String contentType) {
        if (body == null || body.isEmpty() || contentType == null) {
            return new LinkedHashMap<>();
        }

        if (contentType.contains("application/x-www-form-urlencoded")) {
            return parseUrlEncoded(body);
        }
        if (contentType.contains("application/json")) {
            return parseJson(body);
        }
        if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
            return parseXml(body);
        }
        if (contentType.contains("multipart/form-data")) {
            return parseMultipart(body, contentType);
        }
        return new LinkedHashMap<>();
    }

    public static String renderUrlEncoded(Map<String, String> params) {
        return renderUrlEncoded(toLocatedParameters(params));
    }

    public static String renderUrlEncoded(List<LocatedParameter> params) {
        StringBuilder body = new StringBuilder();
        for (LocatedParameter parameter : params) {
            if (body.length() > 0) {
                body.append("&");
            }
            body.append(urlEncode(flattenedName(parameter))).append("=").append(urlEncode(parameter.value()));
        }
        return body.toString();
    }

    public static String renderJson(Map<String, String> params) {
        return renderJson(toLocatedParameters(params));
    }

    public static String renderJson(List<LocatedParameter> params) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (LocatedParameter parameter : params) {
            if (!first) {
                json.append(",");
            }
            json.append("\"").append(escapeJson(flattenedName(parameter))).append("\":")
                .append("\"").append(escapeJson(parameter.value())).append("\"");
            first = false;
        }
        json.append("}");
        return json.toString();
    }

    public static String renderXml(Map<String, String> params) {
        return renderXml(toLocatedParameters(params));
    }

    public static String renderXml(List<LocatedParameter> params) {
        StringBuilder xml = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root>\n");
        for (LocatedParameter parameter : params) {
            String name = flattenedName(parameter);
            xml.append("  <").append(escapeXml(name)).append(">")
                .append(escapeXml(parameter.value()))
                .append("</").append(escapeXml(name)).append(">\n");
        }
        xml.append("</root>");
        return xml.toString();
    }

    public static String renderMultipart(Map<String, String> params, String boundary) {
        return renderMultipart(toLocatedParameters(params), boundary);
    }

    public static String renderMultipart(List<LocatedParameter> params, String boundary) {
        StringBuilder body = new StringBuilder();
        for (LocatedParameter parameter : params) {
            body.append("--").append(boundary).append("\r\n");
            body.append("Content-Disposition: form-data; name=\"").append(flattenedName(parameter)).append("\"\r\n\r\n");
            body.append(parameter.value()).append("\r\n");
        }
        body.append("--").append(boundary).append("--\r\n");
        return body.toString();
    }

    private static Map<String, String> parseUrlEncoded(String body) {
        Map<String, String> params = new LinkedHashMap<>();
        for (LocatedParameter parameter : parseUrlEncodedLocatedParameters(body)) {
            params.put(parameter.name(), parameter.value());
        }
        return params;
    }

    private static Map<String, String> parseJson(String body) {
        Map<String, String> params = new LinkedHashMap<>();
        try {
            JsonElement root = JsonParser.parseString(body);
            if (!root.isJsonObject()) {
                return params;
            }

            JsonObject object = root.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
                params.put(entry.getKey(), jsonValueToParameterValue(entry.getValue()));
            }
        } catch (Exception e) {
            return params;
        }
        return params;
    }

    private static Map<String, String> parseXml(String body) {
        Map<String, String> params = new LinkedHashMap<>();
        try {
            Document document = parseXmlDocument(body);
            Element root = document.getDocumentElement();
            if (root == null) {
                return params;
            }

            for (Node child = root.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (child.getNodeType() == Node.ELEMENT_NODE) {
                    String value = child.getTextContent();
                    params.put(child.getNodeName(), value == null ? "" : value.trim());
                }
            }
        } catch (Exception e) {
            return params;
        }
        return params;
    }

    private static List<LocatedParameter> parseBodyLocatedParameters(String body, String contentType) {
        if (body == null || body.isEmpty() || contentType == null) {
            return List.of();
        }

        if (contentType.contains("application/x-www-form-urlencoded")) {
            return parseUrlEncodedLocatedParameters(body);
        }
        if (contentType.contains("application/json")) {
            return parseJsonLocatedParameters(body);
        }
        if (contentType.contains("application/xml") || contentType.contains("text/xml")) {
            return parseXmlLocatedParameters(body);
        }
        if (contentType.contains("multipart/form-data")) {
            return parseMultipartLocatedParameters(body, contentType);
        }
        return List.of();
    }

    private static Map<String, String> parseMultipart(String body, String contentType) {
        Map<String, String> params = new LinkedHashMap<>();
        String boundary = extractBoundary(contentType);
        if (boundary == null) {
            return params;
        }

        try {
            for (MultipartPart part : parseMultipartParts(body, boundary)) {
                if (part.name() != null) {
                    params.put(part.name(), part.value());
                }
            }
        } catch (Exception e) {
            return params;
        }
        return params;
    }

    private static String replaceFormParameterName(String body, LocatedParameter target, String newName) {
        List<LocatedParameter> params = parseUrlEncodedLocatedParameters(body);
        if (!replaceParameterName(params, target, newName)) {
            return body;
        }
        return renderUrlEncoded(params);
    }

    private static String replaceFormParameterValue(String body, LocatedParameter target, String newValue) {
        List<LocatedParameter> params = parseUrlEncodedLocatedParameters(body);
        if (!replaceParameterValue(params, target, newValue)) {
            return body;
        }
        return renderUrlEncoded(params);
    }

    private static String replaceJsonParameterName(String body, LocatedParameter target, String newName) {
        try {
            JsonElement root = JsonParser.parseString(body);
            List<String> tokens = jsonTokens(target);
            if (tokens.isEmpty() || isArrayIndex(tokens.get(tokens.size() - 1))) {
                return body;
            }
            JsonElement parent = navigateJsonParent(root, tokens);
            if (!(parent instanceof JsonObject object)) {
                return body;
            }

            String oldName = tokens.get(tokens.size() - 1);
            if (!object.has(oldName)) {
                return body;
            }
            JsonObject renamed = new JsonObject();
            for (Map.Entry<String, JsonElement> entry : object.entrySet()) {
                renamed.add(entry.getKey().equals(oldName) ? newName : entry.getKey(), entry.getValue());
            }
            if (tokens.size() == 1) {
                return GSON.toJson(renamed);
            }
            replaceJsonChild(root, tokens.subList(0, tokens.size() - 1), renamed);
            return GSON.toJson(root);
        } catch (Exception e) {
            return body;
        }
    }

    private static String replaceJsonParameterValue(String body, LocatedParameter target, String newValue) {
        try {
            JsonElement root = JsonParser.parseString(body);
            List<String> tokens = jsonTokens(target);
            if (tokens.isEmpty()) {
                return body;
            }
            if (!replaceJsonValue(root, tokens, newValue)) {
                return body;
            }
            return GSON.toJson(root);
        } catch (Exception e) {
            return body;
        }
    }

    private static String replaceJsonParameterValueWithJson(String body, LocatedParameter target, String rawJsonValue) {
        try {
            JsonElement root = JsonParser.parseString(body);
            List<String> tokens = jsonTokens(target);
            if (tokens.isEmpty()) {
                return body;
            }
            JsonElement replacement = "null".equals(rawJsonValue.trim())
                ? JsonNull.INSTANCE
                : JsonParser.parseString(rawJsonValue);
            if (!replaceJsonValue(root, tokens, replacement)) {
                return body;
            }
            return GSON.toJson(root);
        } catch (Exception e) {
            return body;
        }
    }

    private static String replaceJsonParameterValuePreservingRawJson(String body, LocatedParameter target, String rawJsonValue) {
        try {
            List<String> tokens = jsonTokens(target);
            if (tokens.isEmpty()) {
                return body;
            }

            String leaf = tokens.get(tokens.size() - 1);
            if (isArrayIndex(leaf)) {
                return replaceJsonParameterValueWithJson(body, target, rawJsonValue);
            }

            JsonElement root = JsonParser.parseString(body);
            JsonElement currentValue = findJsonElement(root, tokens);
            if (currentValue == null) {
                return body;
            }

            String currentRawJsonValue = GSON.toJson(currentValue);
            String propertyPattern = "\""
                + Pattern.quote(leaf)
                + "\"\\s*:\\s*"
                + Pattern.quote(currentRawJsonValue);
            String replacement = "\"" + leaf + "\":" + rawJsonValue;
            String updated = body.replaceFirst(propertyPattern, Matcher.quoteReplacement(replacement));
            if (!updated.equals(body)) {
                return updated;
            }

            return replaceJsonParameterValueWithJson(body, target, rawJsonValue);
        } catch (Exception e) {
            return body;
        }
    }

    private static String replaceJsonParameterWithDuplicateKeys(String body,
                                                                LocatedParameter target,
                                                                String firstRawJsonValue,
                                                                String secondRawJsonValue) {
        try {
            List<String> tokens = jsonTokens(target);
            if (tokens.isEmpty()) {
                return body;
            }

            String leaf = tokens.get(tokens.size() - 1);
            if (isArrayIndex(leaf)) {
                return body;
            }

            JsonElement root = JsonParser.parseString(body);
            JsonElement currentValue = findJsonElement(root, tokens);
            if (currentValue == null) {
                return body;
            }

            String currentRawJsonValue = GSON.toJson(currentValue);
            String propertyPattern = "\""
                + Pattern.quote(leaf)
                + "\"\\s*:\\s*"
                + Pattern.quote(currentRawJsonValue);
            String replacement = "\"" + leaf + "\":" + firstRawJsonValue
                + ",\"" + leaf + "\":" + secondRawJsonValue;
            return body.replaceFirst(propertyPattern, Matcher.quoteReplacement(replacement));
        } catch (Exception e) {
            return body;
        }
    }

    private static String replaceXmlParameterName(String body, LocatedParameter target, String newName) {
        try {
            Document document = parseXmlDocument(body);
            Node node = findXmlNode(document, target.path());
            if (node == null && !target.path().startsWith("/")) {
                node = firstXmlNodeByName(document, target.name());
            }
            if (node == null) {
                return body;
            }
            document.renameNode(node, node.getNamespaceURI(), newName);
            return renderXmlDocument(document);
        } catch (Exception e) {
            return body;
        }
    }

    private static String replaceXmlParameterValue(String body, LocatedParameter target, String newValue) {
        try {
            Document document = parseXmlDocument(body);
            Node node = findXmlNode(document, target.path());
            if (node == null && !target.path().startsWith("/")) {
                node = firstXmlNodeByName(document, target.name());
            }
            if (node == null) {
                return body;
            }
            node.setTextContent(newValue);
            return renderXmlDocument(document);
        } catch (Exception e) {
            return body;
        }
    }

    private static String replaceMultipartParameterName(String body, String contentType, LocatedParameter target, String newName) {
        String boundary = extractBoundary(contentType);
        if (boundary == null) {
            return body;
        }

        try {
            List<MultipartPart> parts = parseMultipartParts(body, boundary);
            int matched = 0;
            for (int i = 0; i < parts.size(); i++) {
                MultipartPart part = parts.get(i);
                if (!target.name().equals(part.name())) {
                    continue;
                }
                if (target.occurrence() >= 0 && matched != target.occurrence()) {
                    matched++;
                    continue;
                }
                parts.set(i, part.withName(newName));
                return renderMultipartParts(parts, boundary, detectLineSeparator(body));
            }
            return body;
        } catch (Exception e) {
            return body;
        }
    }

    private static String replaceMultipartParameterValue(String body, String contentType, LocatedParameter target, String newValue) {
        String boundary = extractBoundary(contentType);
        if (boundary == null) {
            return body;
        }

        try {
            List<MultipartPart> parts = parseMultipartParts(body, boundary);
            int matched = 0;
            for (int i = 0; i < parts.size(); i++) {
                MultipartPart part = parts.get(i);
                if (!target.name().equals(part.name())) {
                    continue;
                }
                if (target.occurrence() >= 0 && matched != target.occurrence()) {
                    matched++;
                    continue;
                }
                parts.set(i, part.withValue(newValue));
                return renderMultipartParts(parts, boundary, detectLineSeparator(body));
            }
            return body;
        } catch (Exception e) {
            return body;
        }
    }

    private static List<LocatedParameter> parseUrlEncodedLocatedParameters(String body) {
        List<LocatedParameter> params = new ArrayList<>();
        Map<String, Integer> occurrences = new LinkedHashMap<>();
        String[] pairs = body.split("&");
        for (String pair : pairs) {
            if (pair.isEmpty()) {
                continue;
            }

            int idx = pair.indexOf('=');
            String name = idx > 0 ? decode(pair.substring(0, idx)) : decode(pair);
            String value = idx > -1 && idx < pair.length() - 1 ? decode(pair.substring(idx + 1)) : "";
            params.add(new LocatedParameter(
                name,
                value,
                ParameterLocation.BODY,
                name,
                nextOccurrence(occurrences, name)
            ));
        }
        return params;
    }

    private static List<LocatedParameter> parseJsonLocatedParameters(String body) {
        List<LocatedParameter> params = new ArrayList<>();
        try {
            JsonElement root = JsonParser.parseString(body);
            collectJsonParameters(root, new ArrayList<>(), params);
        } catch (Exception e) {
            return List.of();
        }
        return params;
    }

    private static void collectJsonParameters(JsonElement element, List<String> path, List<LocatedParameter> params) {
        if (element == null || element.isJsonNull() || element.isJsonPrimitive()) {
            if (!path.isEmpty()) {
                params.add(new LocatedParameter(
                    displayNameForJsonPath(path),
                    jsonValueToParameterValue(element),
                    ParameterLocation.BODY,
                    toJsonPath(path),
                    -1
                ));
            }
            return;
        }

        if (element.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : element.getAsJsonObject().entrySet()) {
                List<String> childPath = new ArrayList<>(path);
                childPath.add(entry.getKey());
                collectJsonParameters(entry.getValue(), childPath, params);
            }
            return;
        }

        for (int i = 0; i < element.getAsJsonArray().size(); i++) {
            List<String> childPath = new ArrayList<>(path);
            childPath.add(String.valueOf(i));
            collectJsonParameters(element.getAsJsonArray().get(i), childPath, params);
        }
    }

    private static List<LocatedParameter> parseXmlLocatedParameters(String body) {
        List<LocatedParameter> params = new ArrayList<>();
        try {
            Document document = parseXmlDocument(body);
            Element root = document.getDocumentElement();
            if (root == null) {
                return params;
            }
            collectXmlParameters(root, "/" + root.getTagName() + "[0]", params);
        } catch (Exception e) {
            return List.of();
        }
        return params;
    }

    private static void collectXmlParameters(Element element, String path, List<LocatedParameter> params) {
        List<Element> children = childElements(element);
        if (children.isEmpty()) {
            String value = element.getTextContent() == null ? "" : element.getTextContent().trim();
            params.add(new LocatedParameter(element.getTagName(), value, ParameterLocation.BODY, path, -1));
            return;
        }

        Map<String, Integer> siblingCounts = new LinkedHashMap<>();
        for (Element child : children) {
            int index = nextOccurrence(siblingCounts, child.getTagName());
            collectXmlParameters(child, path + "/" + child.getTagName() + "[" + index + "]", params);
        }
    }

    private static List<LocatedParameter> parseMultipartLocatedParameters(String body, String contentType) {
        String boundary = extractBoundary(contentType);
        if (boundary == null) {
            return List.of();
        }

        try {
            List<LocatedParameter> params = new ArrayList<>();
            Map<String, Integer> occurrences = new LinkedHashMap<>();
            for (MultipartPart part : parseMultipartParts(body, boundary)) {
                if (part.name() == null) {
                    continue;
                }
                params.add(new LocatedParameter(
                    part.name(),
                    part.value(),
                    ParameterLocation.BODY,
                    part.name(),
                    nextOccurrence(occurrences, part.name())
                ));
            }
            return params;
        } catch (Exception e) {
            return List.of();
        }
    }

    private static boolean replaceParameterName(List<LocatedParameter> params, LocatedParameter target, String newName) {
        for (int i = 0; i < params.size(); i++) {
            LocatedParameter parameter = params.get(i);
            if (matches(parameter, target)) {
                params.set(i, new LocatedParameter(newName, parameter.value(), parameter.location(), newName, parameter.occurrence()));
                return true;
            }
        }
        return false;
    }

    private static boolean replaceParameterValue(List<LocatedParameter> params, LocatedParameter target, String newValue) {
        for (int i = 0; i < params.size(); i++) {
            LocatedParameter parameter = params.get(i);
            if (matches(parameter, target)) {
                params.set(i, new LocatedParameter(parameter.name(), newValue, parameter.location(), parameter.path(), parameter.occurrence()));
                return true;
            }
        }
        return false;
    }

    private static boolean matches(LocatedParameter actual, LocatedParameter target) {
        if (target.path() != null && !target.path().equals(target.name()) && actual.path().equals(target.path())) {
            return true;
        }
        return actual.name().equals(target.name())
            && actual.location() == target.location()
            && (target.occurrence() < 0 || actual.occurrence() == target.occurrence());
    }

    private static List<LocatedParameter> toLocatedParameters(Map<String, String> params) {
        List<LocatedParameter> locatedParameters = new ArrayList<>(params.size());
        int occurrence = 0;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            locatedParameters.add(new LocatedParameter(
                entry.getKey(),
                entry.getValue(),
                ParameterLocation.BODY,
                entry.getKey(),
                occurrence++
            ));
        }
        return locatedParameters;
    }

    private static String flattenedName(LocatedParameter parameter) {
        if (!parameter.isBody() || parameter.path() == null || parameter.path().isBlank() || parameter.path().equals(parameter.name())) {
            return parameter.name();
        }
        if (parameter.path().startsWith("/")) {
            String flattenedXmlPath = flattenXmlPath(parameter.path());
            if (flattenedXmlPath != null) {
                return flattenedXmlPath;
            }
            return flattenPointer(parameter.path());
        }
        return parameter.path();
    }

    private static String flattenXmlPath(String path) {
        List<XmlSegment> segments = parseXmlPath(path);
        if (segments.isEmpty()) {
            return null;
        }

        StringBuilder flattened = new StringBuilder();
        for (int i = 1; i < segments.size(); i++) {
            XmlSegment segment = segments.get(i);
            if (flattened.length() > 0) {
                flattened.append(".");
            }
            flattened.append(segment.name());
            if (segment.index() > 0) {
                flattened.append("[").append(segment.index()).append("]");
            }
        }
        return flattened.isEmpty() ? segments.get(0).name() : flattened.toString();
    }

    private static String flattenPointer(String path) {
        List<String> tokens = parseJsonPath(path);
        if (tokens.isEmpty()) {
            return path;
        }
        StringBuilder flattened = new StringBuilder();
        for (String token : tokens) {
            if (isArrayIndex(token)) {
                flattened.append("[").append(token).append("]");
            } else {
                if (flattened.length() > 0) {
                    flattened.append(".");
                }
                flattened.append(token);
            }
        }
        return flattened.toString();
    }

    private static int nextOccurrence(Map<String, Integer> occurrences, String name) {
        int occurrence = occurrences.getOrDefault(name, 0);
        occurrences.put(name, occurrence + 1);
        return occurrence;
    }

    private static String displayNameForJsonPath(List<String> path) {
        String last = path.get(path.size() - 1);
        if (!isArrayIndex(last)) {
            return last;
        }
        if (path.size() == 1) {
            return "[" + last + "]";
        }
        return path.get(path.size() - 2) + "[" + last + "]";
    }

    private static String toJsonPath(List<String> path) {
        StringBuilder pointer = new StringBuilder();
        for (String token : path) {
            pointer.append("/").append(token.replace("~", "~0").replace("/", "~1"));
        }
        return pointer.toString();
    }

    private static List<String> parseJsonPath(String path) {
        if (path == null || path.isBlank() || !path.startsWith("/")) {
            return List.of();
        }
        String[] parts = path.substring(1).split("/");
        List<String> tokens = new ArrayList<>(parts.length);
        for (String part : parts) {
            tokens.add(part.replace("~1", "/").replace("~0", "~"));
        }
        return tokens;
    }

    private static List<String> jsonTokens(LocatedParameter target) {
        List<String> tokens = parseJsonPath(target.path());
        if (!tokens.isEmpty()) {
            return tokens;
        }
        return List.of(target.name());
    }

    private static boolean replaceJsonValue(JsonElement root, List<String> tokens, String newValue) {
        JsonElement parent = navigateJsonParent(root, tokens);
        if (parent == null) {
            return false;
        }

        String leaf = tokens.get(tokens.size() - 1);
        if (parent.isJsonObject()) {
            JsonObject object = parent.getAsJsonObject();
            if (!object.has(leaf)) {
                return false;
            }
            object.addProperty(leaf, newValue);
            return true;
        }
        if (parent.isJsonArray() && isArrayIndex(leaf)) {
            int index = Integer.parseInt(leaf);
            if (index < 0 || index >= parent.getAsJsonArray().size()) {
                return false;
            }
            parent.getAsJsonArray().set(index, JsonParser.parseString(GSON.toJson(newValue)));
            return true;
        }
        return false;
    }

    private static boolean replaceJsonValue(JsonElement root, List<String> tokens, JsonElement newValue) {
        JsonElement parent = navigateJsonParent(root, tokens);
        if (parent == null) {
            return false;
        }

        String leaf = tokens.get(tokens.size() - 1);
        if (parent.isJsonObject()) {
            JsonObject object = parent.getAsJsonObject();
            if (!object.has(leaf)) {
                return false;
            }
            object.add(leaf, newValue);
            return true;
        }
        if (parent.isJsonArray() && isArrayIndex(leaf)) {
            int index = Integer.parseInt(leaf);
            if (index < 0 || index >= parent.getAsJsonArray().size()) {
                return false;
            }
            parent.getAsJsonArray().set(index, newValue);
            return true;
        }
        return false;
    }

    private static JsonElement findJsonElement(JsonElement root, List<String> tokens) {
        if (tokens.isEmpty()) {
            return null;
        }

        JsonElement parent = navigateJsonParent(root, tokens);
        if (parent == null) {
            return null;
        }

        String leaf = tokens.get(tokens.size() - 1);
        if (parent.isJsonObject()) {
            return parent.getAsJsonObject().get(leaf);
        }
        if (parent.isJsonArray() && isArrayIndex(leaf)) {
            int index = Integer.parseInt(leaf);
            if (index < 0 || index >= parent.getAsJsonArray().size()) {
                return null;
            }
            return parent.getAsJsonArray().get(index);
        }
        return null;
    }

    private static JsonElement navigateJsonParent(JsonElement root, List<String> tokens) {
        JsonElement current = root;
        for (int i = 0; i < tokens.size() - 1; i++) {
            String token = tokens.get(i);
            if (current == null) {
                return null;
            }
            if (current.isJsonObject()) {
                current = current.getAsJsonObject().get(token);
            } else if (current.isJsonArray() && isArrayIndex(token)) {
                int index = Integer.parseInt(token);
                if (index < 0 || index >= current.getAsJsonArray().size()) {
                    return null;
                }
                current = current.getAsJsonArray().get(index);
            } else {
                return null;
            }
        }
        return current;
    }

    private static void replaceJsonChild(JsonElement root, List<String> parentTokens, JsonElement replacement) {
        if (parentTokens.isEmpty()) {
            return;
        }
        JsonElement grandParent = navigateJsonParent(root, parentTokens);
        if (grandParent == null) {
            return;
        }
        String leaf = parentTokens.get(parentTokens.size() - 1);
        if (grandParent.isJsonObject()) {
            grandParent.getAsJsonObject().add(leaf, replacement);
        } else if (grandParent.isJsonArray() && isArrayIndex(leaf)) {
            grandParent.getAsJsonArray().set(Integer.parseInt(leaf), replacement);
        }
    }

    private static boolean isArrayIndex(String token) {
        for (int i = 0; i < token.length(); i++) {
            if (!Character.isDigit(token.charAt(i))) {
                return false;
            }
        }
        return !token.isEmpty();
    }

    private static List<Element> childElements(Element element) {
        List<Element> children = new ArrayList<>();
        for (Node child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                children.add((Element) child);
            }
        }
        return children;
    }

    private static Node findXmlNode(Document document, String path) {
        if (path == null || path.isBlank() || !path.startsWith("/")) {
            return null;
        }

        List<String> segments = new ArrayList<>();
        for (String segment : path.substring(1).split("/")) {
            if (!segment.isBlank()) {
                segments.add(segment);
            }
        }
        if (segments.isEmpty()) {
            return null;
        }

        Node current = document.getDocumentElement();
        if (current == null || !matchesXmlSegment(current, segments.get(0))) {
            return null;
        }

        for (int i = 1; i < segments.size(); i++) {
            current = findXmlChild(current, segments.get(i));
            if (current == null) {
                return null;
            }
        }
        return current;
    }

    private static Node firstXmlNodeByName(Document document, String name) {
        for (Node node : nodes(document.getElementsByTagName(name))) {
            return node;
        }
        return null;
    }

    private static boolean matchesXmlSegment(Node node, String segment) {
        XmlSegment parsed = parseXmlSegment(segment);
        return parsed != null && parsed.index() == 0 && node.getNodeName().equals(parsed.name());
    }

    private static Node findXmlChild(Node parent, String segment) {
        XmlSegment parsed = parseXmlSegment(segment);
        if (parsed == null) {
            return null;
        }

        int index = 0;
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child.getNodeType() != Node.ELEMENT_NODE || !child.getNodeName().equals(parsed.name())) {
                continue;
            }
            if (index == parsed.index()) {
                return child;
            }
            index++;
        }
        return null;
    }

    private static XmlSegment parseXmlSegment(String segment) {
        Matcher matcher = Pattern.compile("(.+)\\[(\\d+)]").matcher(segment);
        if (!matcher.matches()) {
            return null;
        }
        return new XmlSegment(matcher.group(1), Integer.parseInt(matcher.group(2)));
    }

    private static List<XmlSegment> parseXmlPath(String path) {
        if (path == null || path.isBlank() || !path.startsWith("/")) {
            return List.of();
        }

        List<XmlSegment> segments = new ArrayList<>();
        for (String segment : path.substring(1).split("/")) {
            if (segment.isBlank()) {
                continue;
            }
            XmlSegment parsed = parseXmlSegment(segment);
            if (parsed == null) {
                return List.of();
            }
            segments.add(parsed);
        }
        return segments;
    }

    private static String extractBoundary(String contentType) {
        if (contentType == null || !contentType.contains("boundary=")) {
            return null;
        }

        int boundaryStart = contentType.indexOf("boundary=") + 9;
        String boundary = contentType.substring(boundaryStart).trim();
        int delimiter = boundary.indexOf(';');
        String normalized = delimiter == -1 ? boundary : boundary.substring(0, delimiter);
        if (normalized.length() >= 2 && normalized.startsWith("\"") && normalized.endsWith("\"")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        return normalized;
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t");
    }

    private static String escapeXml(String value) {
        return value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&apos;");
    }

    private static String jsonValueToParameterValue(JsonElement element) {
        if (element == null || element instanceof JsonNull || element.isJsonNull()) {
            return "null";
        }
        if (element.isJsonPrimitive()) {
            return element.getAsJsonPrimitive().getAsString();
        }
        return GSON.toJson(element);
    }

    private static Document parseXmlDocument(String body) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setNamespaceAware(true);

        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(body)));
    }

    private static String renderXmlDocument(Document document) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.INDENT, "no");

        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(writer));
        return writer.toString();
    }

    private static List<Node> nodes(org.w3c.dom.NodeList nodeList) {
        List<Node> nodes = new ArrayList<>(nodeList.getLength());
        for (int i = 0; i < nodeList.getLength(); i++) {
            nodes.add(nodeList.item(i));
        }
        return nodes;
    }

    private static List<MultipartPart> parseMultipartParts(String body, String boundary) {
        List<MultipartPart> parts = new ArrayList<>();
        String delimiter = "--" + boundary;
        String lineSeparator = detectLineSeparator(body);
        int index = body.indexOf(delimiter);

        while (index >= 0) {
            int partStart = index + delimiter.length();
            if (body.startsWith("--", partStart)) {
                break;
            }
            if (body.startsWith(lineSeparator, partStart)) {
                partStart += lineSeparator.length();
            }

            int nextBoundary = body.indexOf(delimiter, partStart);
            if (nextBoundary < 0) {
                break;
            }

            String rawPart = body.substring(partStart, nextBoundary);
            if (rawPart.endsWith(lineSeparator)) {
                rawPart = rawPart.substring(0, rawPart.length() - lineSeparator.length());
            }

            MultipartPart part = parseMultipartPart(rawPart, lineSeparator);
            if (part != null) {
                parts.add(part);
            }

            index = nextBoundary;
        }

        return parts;
    }

    private static MultipartPart parseMultipartPart(String rawPart, String lineSeparator) {
        String separator = lineSeparator + lineSeparator;
        int splitIndex = rawPart.indexOf(separator);
        if (splitIndex < 0) {
            return null;
        }

        String headerSection = rawPart.substring(0, splitIndex);
        String value = rawPart.substring(splitIndex + separator.length());
        List<String> headers = new ArrayList<>();
        for (String headerLine : headerSection.split(Pattern.quote(lineSeparator))) {
            if (!headerLine.isEmpty()) {
                headers.add(headerLine);
            }
        }

        return new MultipartPart(headers, extractMultipartName(headers), value);
    }

    private static String extractMultipartName(List<String> headers) {
        for (String header : headers) {
            if (!header.regionMatches(true, 0, "Content-Disposition:", 0, "Content-Disposition:".length())) {
                continue;
            }
            int nameStart = header.indexOf("name=\"");
            if (nameStart < 0) {
                continue;
            }
            nameStart += 6;
            int nameEnd = header.indexOf('"', nameStart);
            if (nameEnd > nameStart) {
                return header.substring(nameStart, nameEnd);
            }
        }
        return null;
    }

    private static String renderMultipartParts(List<MultipartPart> parts, String boundary, String lineSeparator) {
        String delimiter = "--" + boundary;
        StringBuilder body = new StringBuilder();
        for (MultipartPart part : parts) {
            body.append(delimiter).append(lineSeparator);
            for (String header : part.headers()) {
                body.append(header).append(lineSeparator);
            }
            body.append(lineSeparator);
            body.append(part.value()).append(lineSeparator);
        }
        body.append(delimiter).append("--").append(lineSeparator);
        return body.toString();
    }

    private static String detectLineSeparator(String text) {
        return text != null && text.contains("\r\n") ? "\r\n" : "\n";
    }

    private record MultipartPart(List<String> headers, String name, String value) {
        private MultipartPart withName(String newName) {
            List<String> updatedHeaders = new ArrayList<>(headers.size());
            for (String header : headers) {
                if (header.regionMatches(true, 0, "Content-Disposition:", 0, "Content-Disposition:".length())
                    && name != null) {
                    updatedHeaders.add(header.replace("name=\"" + name + "\"", "name=\"" + newName + "\""));
                } else {
                    updatedHeaders.add(header);
                }
            }
            return new MultipartPart(updatedHeaders, newName, value);
        }

        private MultipartPart withValue(String newValue) {
            return new MultipartPart(headers, name, newValue);
        }
    }

    private record XmlSegment(String name, int index) {
    }
}
