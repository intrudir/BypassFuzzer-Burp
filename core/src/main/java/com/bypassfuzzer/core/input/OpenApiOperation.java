package com.bypassfuzzer.core.input;

import java.net.URI;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** A request template remains inspectable even when some variables have no value yet. */
public record OpenApiOperation(String method, String url, Map<String, String> headers, String body,
                               Source source, Set<String> unresolvedVariables) {
    static final Pattern VARIABLE = Pattern.compile(
        "\\{\\{\\s*([^{}\\s]+)\\s*}}|(?<![{$])\\{([A-Za-z_][A-Za-z0-9_.:-]*)}(?!})");

    public OpenApiOperation(String method, String url, Map<String, String> headers, String body) {
        this(method, url, headers, body, null, Set.of());
    }

    public OpenApiOperation {
        headers = headers == null ? Map.of() : Map.copyOf(headers);
        body = body == null ? "" : body;
        unresolvedVariables = unresolvedVariables == null ? Set.of() : Set.copyOf(unresolvedVariables);
    }

    /** Source identity is independent of the displayed values and parameter policy. */
    public record Source(String server, String path) { }

    /** URI parsing for an editor's synthetic connection; unresolved templates cannot execute. */
    public static URI previewUri(String url) {
        String parseable = VARIABLE.matcher(url).replaceAll("1");
        if (parseable.startsWith("1://")) parseable = "https" + parseable.substring(1);
        return URI.create(parseable);
    }

    public String requestTarget() {
        int start = authorityEnd();
        String target = url.substring(start).split("#", 2)[0];
        return target.isEmpty() ? "/" : target.startsWith("?") ? "/" + target : target;
    }

    public String authority() {
        return url.substring(url.indexOf("://") + 3, authorityEnd());
    }

    private int authorityEnd() {
        int end = url.length();
        for (char separator : new char[]{'/', '?', '#'}) {
            int index = url.indexOf(separator, url.indexOf("://") + 3);
            if (index >= 0) end = Math.min(end, index);
        }
        return end;
    }
}
