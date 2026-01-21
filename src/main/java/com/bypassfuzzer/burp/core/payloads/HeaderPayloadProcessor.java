package com.bypassfuzzer.burp.core.payloads;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

/**
 * Processes header payload templates by substituting placeholders with actual values.
 *
 * Placeholders:
 * - {IP PAYLOAD} - Replaced with IP addresses from ip_payloads.txt
 * - {URL PAYLOAD} - Replaced with full target URL
 * - {PATH PAYLOAD} - Replaced with URL path
 * - {OOB PAYLOAD} - Replaced with out-of-band payload URL (if configured)
 * - {OOB DOMAIN PAYLOAD} - Replaced with OOB domain only
 * - {WHITESPACE PAYLOAD} - Replaced with whitespace character
 */
public class HeaderPayloadProcessor {

    private final String targetUrl;
    private final String targetPath;
    private final String oobPayload;

    public HeaderPayloadProcessor(String targetUrl, String oobPayload) {
        this.targetUrl = targetUrl;
        this.oobPayload = oobPayload;
        this.targetPath = extractPath(targetUrl);
    }

    /**
     * Process header templates with IP payloads and other substitutions.
     *
     * @param headerTemplates List of header templates (e.g., "X-Forwarded-For: {IP PAYLOAD}")
     * @param ipPayloads List of IP addresses to substitute
     * @return Processed list of header payloads ready to use
     */
    public List<String> processHeaderTemplates(List<String> headerTemplates, List<String> ipPayloads) {
        List<String> processedHeaders = new ArrayList<>();

        for (String template : headerTemplates) {
            if (template.contains("{IP PAYLOAD}")) {
                // Expand each IP payload
                for (String ip : ipPayloads) {
                    processedHeaders.add(template.replace("{IP PAYLOAD}", ip));
                }
            } else if (template.contains("{WHITESPACE PAYLOAD}")) {
                processedHeaders.add(template.replace("{WHITESPACE PAYLOAD}", " "));
            } else if (template.contains("{URL PAYLOAD}")) {
                processedHeaders.add(template.replace("{URL PAYLOAD}", targetUrl));
            } else if (template.contains("{PATH PAYLOAD}")) {
                processedHeaders.add(template.replace("{PATH PAYLOAD}", targetPath));
            } else if (template.contains("{OOB PAYLOAD}")) {
                if (oobPayload != null && !oobPayload.isEmpty()) {
                    String oobDomain = extractDomain(oobPayload);
                    processedHeaders.add(template.replace("{OOB PAYLOAD}", "http://" + oobDomain));
                    processedHeaders.add(template.replace("{OOB PAYLOAD}", "https://" + oobDomain));
                }
            } else if (template.contains("{OOB DOMAIN PAYLOAD}")) {
                if (oobPayload != null && !oobPayload.isEmpty()) {
                    String oobDomain = extractDomain(oobPayload);
                    processedHeaders.add(template.replace("{OOB DOMAIN PAYLOAD}", oobDomain));
                }
            } else {
                // No placeholder, add as-is
                processedHeaders.add(template);
            }
        }

        return processedHeaders;
    }

    private String extractPath(String url) {
        try {
            URI uri = new URI(url);
            String path = uri.getPath();
            return path != null && !path.isEmpty() ? path : "/";
        } catch (URISyntaxException e) {
            return "/";
        }
    }

    private String extractDomain(String oobPayload) {
        try {
            URI uri = new URI(oobPayload);
            if (uri.getHost() != null) {
                return uri.getHost();
            } else {
                return oobPayload.replace("http://", "").replace("https://", "");
            }
        } catch (URISyntaxException e) {
            return oobPayload.replace("http://", "").replace("https://", "");
        }
    }
}
