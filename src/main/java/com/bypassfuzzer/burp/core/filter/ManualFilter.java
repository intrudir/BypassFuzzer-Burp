package com.bypassfuzzer.burp.core.filter;

import com.bypassfuzzer.burp.core.attacks.AttackResult;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.net.URI;

/**
 * Manual filter based on user-defined rules.
 */
public class ManualFilter implements ResponseFilter {
    private final FilterConfig config;

    public ManualFilter(FilterConfig config) {
        this.config = config;
    }

    @Override
    public boolean shouldShow(AttackResult result) {
        if (!config.isManualFilterEnabled()) {
            return true; // Filter disabled, show all
        }

        // Check hidden status codes (blacklist)
        if (!config.getHiddenStatusCodes().isEmpty()) {
            if (config.getHiddenStatusCodes().contains(result.getStatusCode())) {
                return false; // Explicitly hidden
            }
        }

        // Check shown status codes (whitelist - if configured, only show these)
        if (!config.getShownStatusCodes().isEmpty()) {
            if (!config.getShownStatusCodes().contains(result.getStatusCode())) {
                return false; // Not in whitelist
            }
        }

        // Check content length range
        Integer minLength = config.getMinContentLength();
        Integer maxLength = config.getMaxContentLength();

        if (minLength != null && result.getContentLength() < minLength) {
            return false; // Below minimum
        }

        if (maxLength != null && result.getContentLength() > maxLength) {
            return false; // Above maximum
        }

        // Check hidden content lengths (blacklist)
        if (!config.getHiddenContentLengths().isEmpty()) {
            if (config.getHiddenContentLengths().contains(result.getContentLength())) {
                return false; // Explicitly hidden
            }
        }

        // Check shown content lengths (whitelist - if configured, only show these)
        if (!config.getShownContentLengths().isEmpty()) {
            if (!config.getShownContentLengths().contains(result.getContentLength())) {
                return false; // Not in whitelist
            }
        }

        // Check content-type filter
        String contentTypeFilter = config.getContentTypeFilter();
        if (contentTypeFilter != null && !contentTypeFilter.trim().isEmpty()) {
            String resultContentType = result.getContentType();
            if (resultContentType == null) {
                return false; // No content-type = filtered out
            }
            // Case-insensitive contains check
            if (!resultContentType.toLowerCase().contains(contentTypeFilter.toLowerCase())) {
                return false; // Content-type doesn't match filter
            }
        }

        // Check payload contains filter
        String payloadFilter = config.getPayloadContainsFilter();
        if (payloadFilter != null && !payloadFilter.trim().isEmpty()) {
            String payload = result.getPayload();
            if (payload == null) {
                return false; // No payload = filtered out
            }
            if (!containsIgnoreCase(payload, payloadFilter)) {
                return false; // Payload doesn't contain filter text
            }
        }

        String hostFilter = config.getHostContainsFilter();
        if (hostFilter != null && !hostFilter.trim().isEmpty()) {
            String host = requestHost(result);
            if (host == null || !containsIgnoreCase(host, hostFilter)) {
                return false;
            }
        }

        String signalFilter = config.getSignalContainsFilter();
        if (signalFilter != null && !signalFilter.trim().isEmpty()) {
            String signal = result.getSignal();
            if (signal == null || signal.isBlank()
                || !matchesFilter(signal, signalFilter, config.isSignalContainsRegex())) {
                return false;
            }
        }

        String responseFilter = config.getResponseContainsFilter();
        if (responseFilter != null && !responseFilter.trim().isEmpty()) {
            String responseText = responseText(result);
            if (responseText == null) {
                return false; // No HTTP response cannot satisfy either response-body predicate
            }
            boolean matches = matchesResponseFilter(
                responseText, responseFilter, config.isResponseContainsRegex());
            if (config.isResponseMatchInverted() ? matches : !matches) {
                return false;
            }
        }

        return true; // Passes all filters
    }

    @Override
    public String getName() {
        return "Manual Filter";
    }

    private boolean containsIgnoreCase(String value, String filter) {
        return value.toLowerCase().contains(filter.toLowerCase());
    }

    private String responseText(AttackResult result) {
        if (result.getResponse() == null) {
            return null;
        }
        return String.valueOf(result.getResponse());
    }

    private boolean matchesResponseFilter(String responseText, String filter, boolean regex) {
        return matchesFilter(responseText, filter, regex);
    }

    private String requestHost(AttackResult result) {
        if (result == null || result.getRequest() == null) {
            return null;
        }
        try {
            if (result.getRequest().httpService() != null) {
                return result.getRequest().httpService().host();
            }
        } catch (Exception ignored) {
        }
        try {
            return URI.create(result.getRequest().url()).getHost();
        } catch (Exception ignored) {
            return null;
        }
    }

    private boolean matchesFilter(String value, String filter, boolean regex) {
        if (!regex) {
            return containsIgnoreCase(value, filter);
        }

        try {
            return Pattern.compile(filter, Pattern.CASE_INSENSITIVE | Pattern.DOTALL)
                .matcher(value)
                .find();
        } catch (PatternSyntaxException e) {
            return false;
        }
    }
}
