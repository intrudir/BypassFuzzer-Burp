package com.bypassfuzzer.core.http;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Helpers for path and query extraction without relying on Burp scope state.
 */
public final class RequestPathUtils {

    private RequestPathUtils() {
    }

    public static String extractPath(String url) {
        try {
            URI uri = new URI(url);
            String path = uri.getRawPath();
            return path == null || path.isEmpty() ? "/" : path;
        } catch (URISyntaxException e) {
            return "/";
        }
    }

    public static String extractPathAndQuery(String url) {
        try {
            URI uri = new URI(url);
            String path = extractPath(url);
            String query = uri.getRawQuery();
            return query == null || query.isEmpty() ? path : path + "?" + query;
        } catch (URISyntaxException e) {
            return "/";
        }
    }

    public static String queryFromPath(String pathWithQuery) {
        if (pathWithQuery == null) {
            return "";
        }

        int queryStart = pathWithQuery.indexOf('?');
        if (queryStart == -1 || queryStart == pathWithQuery.length() - 1) {
            return "";
        }

        return pathWithQuery.substring(queryStart + 1);
    }

    public static String pathWithoutQuery(String pathWithQuery) {
        if (pathWithQuery == null || pathWithQuery.isEmpty()) {
            return "/";
        }

        int queryStart = pathWithQuery.indexOf('?');
        return queryStart == -1 ? pathWithQuery : pathWithQuery.substring(0, queryStart);
    }

    public static String replaceQuery(String pathWithQuery, String query) {
        String basePath = pathWithoutQuery(pathWithQuery);
        if (query == null || query.isEmpty()) {
            return basePath;
        }
        return basePath + "?" + query;
    }

    public static String appendQueryParameter(String pathWithQuery, String parameter) {
        if (parameter == null || parameter.isEmpty()) {
            return pathWithQuery;
        }

        if (pathWithQuery == null || pathWithQuery.isEmpty()) {
            return "/?" + parameter;
        }

        if (!pathWithQuery.contains("?")) {
            return pathWithQuery + "?" + parameter;
        }

        if (pathWithQuery.endsWith("?") || pathWithQuery.endsWith("&")) {
            return pathWithQuery + parameter;
        }

        return pathWithQuery + "&" + parameter;
    }
}
