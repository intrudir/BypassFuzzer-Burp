package com.bypassfuzzer.burp.http;
import com.bypassfuzzer.core.http.UserAgentMode;
import com.bypassfuzzer.core.http.ConfiguredHeader;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.bypassfuzzer.core.http.*;
import java.util.List;
import java.util.Set;

/** Montoya boundary for the shared always-send header policy. */
public final class ConfiguredHeaderPolicy {
    private final RequestHeaderPolicy<HttpRequest> delegate;
    public ConfiguredHeaderPolicy(List<ConfiguredHeader> headers) { this(headers, UserAgentMode.DISABLED, 0); }
    public ConfiguredHeaderPolicy(List<ConfiguredHeader> headers, UserAgentMode mode, long seed) {
        this(new RequestHeaderPolicy<>(MontoyaRequestAccess.INSTANCE, headers, mode, seed));
    }
    private ConfiguredHeaderPolicy(RequestHeaderPolicy<HttpRequest> delegate) { this.delegate = delegate; }
    public RequestHeaderPolicy<HttpRequest> shared() { return delegate; }
    public List<ConfiguredHeader> headers() { return delegate.headers(); }
    public HttpRequest applyToBase(HttpRequest request) { return delegate.applyToBase(request); }
    public HttpRequest reconcileMutation(HttpRequest request) { return reconcileMutation(request, request); }
    public HttpRequest reconcileMutation(HttpRequest baseline, HttpRequest request) {
        return delegate.reconcileMutation(baseline, request);
    }
    public ConfiguredHeaderPolicy withoutAuthentication(Set<String> headers, Set<String> cookies) {
        return new ConfiguredHeaderPolicy(delegate.withoutAuthentication(headers, cookies));
    }
}
