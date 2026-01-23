package com.bypassfuzzer.burp.core.payloads;

import burp.api.montoya.MontoyaApi;

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
 * - {PATH SWAP} - Replaced with URL path + marker; signals HeaderAttack to swap request path to /
 * - {OOB PAYLOAD} - Replaced with dynamically generated Burp Collaborator payload URLs (http:// and https://)
 * - {OOB DOMAIN PAYLOAD} - Replaced with dynamically generated Burp Collaborator domain only
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
        return processHeaderTemplates(headerTemplates, ipPayloads, null);
    }

    /**
     * Process header templates with IP payloads and other substitutions, including dynamic Collaborator payloads.
     *
     * @param headerTemplates List of header templates (e.g., "X-Forwarded-For: {IP PAYLOAD}")
     * @param ipPayloads List of IP addresses to substitute
     * @param api MontoyaApi instance for generating Collaborator payloads (can be null to disable Collaborator)
     * @return Processed list of header payloads ready to use
     */
    public List<String> processHeaderTemplates(List<String> headerTemplates, List<String> ipPayloads, MontoyaApi api) {
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
            } else if (template.contains("{PATH SWAP}")) {
                // PATH SWAP: marker signals HeaderAttack to swap request path to /
                processedHeaders.add(template.replace("{PATH SWAP}", targetPath + " [PATH_SWAP]"));
            } else if (template.contains("{OOB PAYLOAD}")) {
                // Try to generate dynamic Collaborator payload first
                String collaboratorPayload = generateCollaboratorPayload(api);
                if (collaboratorPayload != null) {
                    // Use dynamically generated Collaborator payload
                    processedHeaders.add(template.replace("{OOB PAYLOAD}", "http://" + collaboratorPayload));
                    processedHeaders.add(template.replace("{OOB PAYLOAD}", "https://" + collaboratorPayload));
                } else if (oobPayload != null && !oobPayload.isEmpty()) {
                    // Fallback to static OOB payload if configured
                    String oobDomain = extractDomain(oobPayload);
                    processedHeaders.add(template.replace("{OOB PAYLOAD}", "http://" + oobDomain));
                    processedHeaders.add(template.replace("{OOB PAYLOAD}", "https://" + oobDomain));
                }
            } else if (template.contains("{OOB DOMAIN PAYLOAD}")) {
                // Try to generate dynamic Collaborator payload first
                String collaboratorPayload = generateCollaboratorPayload(api);
                if (collaboratorPayload != null) {
                    // Use dynamically generated Collaborator payload (just the domain)
                    processedHeaders.add(template.replace("{OOB DOMAIN PAYLOAD}", collaboratorPayload));
                } else if (oobPayload != null && !oobPayload.isEmpty()) {
                    // Fallback to static OOB payload if configured
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

    /**
     * Generate a Burp Collaborator payload if Collaborator is available.
     *
     * @param api MontoyaApi instance (can be null)
     * @return Collaborator domain string, or null if unavailable
     */
    private String generateCollaboratorPayload(MontoyaApi api) {
        if (api == null) {
            return null;
        }

        try {
            if (api.collaborator() != null && api.collaborator().defaultPayloadGenerator() != null) {
                return api.collaborator().defaultPayloadGenerator().generatePayload().toString();
            }
        } catch (Exception e) {
            // Collaborator not available or error generating payload
        }

        return null;
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
