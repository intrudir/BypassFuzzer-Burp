package com.bypassfuzzer.core.http;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Query-string parsing and rewriting helpers that preserve parameter order.
 */
public final class QueryStringUtils {

    private QueryStringUtils() {
    }

    public static Map<String, String> parseRaw(String query) {
        return parse(query, false);
    }

    public static Map<String, String> parseDecoded(String query) {
        return parse(query, true);
    }

    public static Map<String, String> parsePathQueryDecoded(String pathWithQuery) {
        return parseDecoded(RequestPathUtils.queryFromPath(pathWithQuery));
    }

    public static List<QueryParameter> parseRawParameters(String query) {
        return parseParameters(query, false);
    }

    public static List<QueryParameter> parseDecodedParameters(String query) {
        return parseParameters(query, true);
    }

    private static Map<String, String> parse(String query, boolean decodeValues) {
        Map<String, String> params = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) {
            return params;
        }

        String[] pairs = query.split("&");
        for (String pair : pairs) {
            if (pair.isEmpty()) {
                continue;
            }

            int eqIdx = pair.indexOf('=');
            if (eqIdx > 0) {
                String name = pair.substring(0, eqIdx);
                String value = eqIdx < pair.length() - 1 ? pair.substring(eqIdx + 1) : "";
                params.put(name, decodeValues ? decode(value) : value);
            } else {
                params.put(pair, "");
            }
        }

        return params;
    }

    public static String toQueryString(Map<String, String> params) {
        StringBuilder query = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (query.length() > 0) {
                query.append("&");
            }
            query.append(entry.getKey()).append("=").append(entry.getValue());
        }
        return query.toString();
    }

    public static String replaceValue(String pathWithQuery, String parameterName, String value) {
        return replaceValue(pathWithQuery, parameterName, value, -1);
    }

    public static String replaceValue(String pathWithQuery, String parameterName, String value, int occurrence) {
        List<QueryParameter> parameters = parseRawParameters(RequestPathUtils.queryFromPath(pathWithQuery));
        boolean replaced = false;
        int matched = 0;

        for (int i = 0; i < parameters.size(); i++) {
            QueryParameter parameter = parameters.get(i);
            if (parameter.name().equals(parameterName)) {
                if (occurrence < 0 || matched == occurrence) {
                    parameters.set(i, parameter.withValue(value));
                    replaced = true;
                    if (occurrence >= 0) {
                        break;
                    }
                }
                matched++;
            }
        }

        if (!replaced) {
            return pathWithQuery;
        }

        return RequestPathUtils.replaceQuery(pathWithQuery, toQueryString(parameters));
    }

    public static String replaceName(String pathWithQuery, String oldName, String newName) {
        return replaceName(pathWithQuery, oldName, newName, -1);
    }

    public static String replaceName(String pathWithQuery, String oldName, String newName, int occurrence) {
        List<QueryParameter> parameters = parseRawParameters(RequestPathUtils.queryFromPath(pathWithQuery));
        boolean replaced = false;
        int matched = 0;

        for (int i = 0; i < parameters.size(); i++) {
            QueryParameter parameter = parameters.get(i);
            if (parameter.name().equals(oldName)) {
                if (occurrence < 0 || matched == occurrence) {
                    parameters.set(i, parameter.withName(newName));
                    replaced = true;
                    if (occurrence >= 0) {
                        break;
                    }
                }
                matched++;
            }
        }

        if (!replaced) {
            return pathWithQuery;
        }

        return RequestPathUtils.replaceQuery(pathWithQuery, toQueryString(parameters));
    }

    public static String upsertParameter(String pathWithQuery, String parameter) {
        if (parameter == null || parameter.isEmpty()) {
            return pathWithQuery;
        }

        QueryParameter target = parseRawParameters(parameter).stream().findFirst().orElse(new QueryParameter(parameter, "", false));
        List<QueryParameter> parameters = parseRawParameters(RequestPathUtils.queryFromPath(pathWithQuery));
        boolean replaced = false;

        for (int i = 0; i < parameters.size(); i++) {
            QueryParameter existing = parameters.get(i);
            if (existing.name().equals(target.name())) {
                parameters.set(i, target);
                replaced = true;
            }
        }

        if (replaced) {
            return RequestPathUtils.replaceQuery(pathWithQuery, toQueryString(parameters));
        }

        return RequestPathUtils.appendQueryParameter(pathWithQuery, parameter);
    }

    public static String upsertDecodedParameter(String pathWithQuery, String parameterName, String parameterValue) {
        if (parameterName == null || parameterName.isBlank()) {
            return pathWithQuery;
        }

        String encodedName = encode(parameterName);
        String encodedValue = encode(parameterValue == null ? "" : parameterValue);
        return upsertParameter(pathWithQuery, encodedName + "=" + encodedValue);
    }

    public static String removeParameter(String pathWithQuery, String parameterName) {
        String path = RequestPathUtils.pathWithoutQuery(pathWithQuery);
        String query = RequestPathUtils.queryFromPath(pathWithQuery);
        if (query == null || query.isEmpty()) {
            return pathWithQuery;
        }
        String encodedName = encode(parameterName);
        StringBuilder filtered = new StringBuilder();
        for (String pair : query.split("&")) {
            String pairName = pair.contains("=") ? pair.substring(0, pair.indexOf('=')) : pair;
            if (pairName.equals(parameterName) || pairName.equals(encodedName)) {
                continue;
            }
            if (!filtered.isEmpty()) {
                filtered.append('&');
            }
            filtered.append(pair);
        }
        if (filtered.isEmpty()) {
            return path;
        }
        return path + "?" + filtered;
    }

    public static String appendDecodedParameter(String pathWithQuery, String parameterName, String parameterValue) {
        if (parameterName == null || parameterName.isBlank()) {
            return pathWithQuery;
        }

        String encodedName = encode(parameterName);
        String encodedValue = encode(parameterValue == null ? "" : parameterValue);
        return RequestPathUtils.appendQueryParameter(pathWithQuery, encodedName + "=" + encodedValue);
    }

    public static String toQueryString(List<QueryParameter> parameters) {
        StringBuilder query = new StringBuilder();
        for (QueryParameter parameter : parameters) {
            if (query.length() > 0) {
                query.append("&");
            }
            query.append(parameter.name());
            if (parameter.hadEquals()) {
                query.append("=").append(parameter.value());
            }
        }
        return query.toString();
    }

    private static List<QueryParameter> parseParameters(String query, boolean decodeValues) {
        List<QueryParameter> parameters = new ArrayList<>();
        if (query == null || query.isEmpty()) {
            return parameters;
        }

        String[] pairs = query.split("&");
        for (String pair : pairs) {
            if (pair.isEmpty()) {
                continue;
            }

            int eqIdx = pair.indexOf('=');
            if (eqIdx > -1) {
                String name = pair.substring(0, eqIdx);
                String value = eqIdx < pair.length() - 1 ? pair.substring(eqIdx + 1) : "";
                parameters.add(new QueryParameter(name, decodeValues ? decode(value) : value, true));
            } else {
                parameters.add(new QueryParameter(pair, "", false));
            }
        }

        return parameters;
    }

    public record QueryParameter(String name, String value, boolean hadEquals) {
        public QueryParameter withName(String newName) {
            return new QueryParameter(newName, value, hadEquals);
        }

        public QueryParameter withValue(String newValue) {
            return new QueryParameter(name, newValue, true);
        }
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private static String encode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }
}
