package com.bypassfuzzer.burp.core.attacks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.bypassfuzzer.burp.core.payloads.HeaderPayloadProcessor;
import com.bypassfuzzer.burp.core.payloads.PayloadLoader;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

public class HeaderAttack implements AttackStrategy {
    private final HeaderPayloadProcessor processor;
    private final List<String> headerPayloads;
    private final boolean enableCollaborator;

    public HeaderAttack(String targetUrl, String oobPayload, boolean enableCollaborator) {
        this.enableCollaborator = enableCollaborator;
        this.processor = new HeaderPayloadProcessor(targetUrl, oobPayload);
        List<String> headerTemplates = PayloadLoader.loadPayloads("header_payload_templates.txt");
        List<String> ipPayloads = PayloadLoader.loadPayloads("ip_payloads.txt");
        this.headerPayloads = processor.processHeaderTemplates(headerTemplates, ipPayloads);
    }

    @Override
    public void execute(MontoyaApi api, HttpRequest baseRequest, String targetUrl, Consumer<AttackResult> resultCallback, BooleanSupplier shouldContinue) {
        try {
            api.logging().logToOutput("Header Attack: Collaborator enabled = " + enableCollaborator);
        } catch (Exception e) {
            // Ignore
        }

        // Build interleaved payload list: group by header name, add Collaborator payload after each group
        List<String> allPayloads = buildInterleavedPayloads(api);

        try {
            api.logging().logToOutput("Starting Header Attack: " + allPayloads.size() + " total payloads" +
                (enableCollaborator ? " (interleaved with Collaborator)" : ""));
        } catch (Exception e) {
            return;
        }

        int count = 0;

        for (String payload : allPayloads) {
            if (!shouldContinue.getAsBoolean()) {
                try {
                    api.logging().logToOutput("Header Attack stopped by user (" + count + " of " + allPayloads.size() + " completed)");
                } catch (Exception e) {
                    // Ignore
                }
                break;
            }

            // Log progress every 100 requests
            if (count % 100 == 0 && count > 0) {
                try {
                    api.logging().logToOutput("Header Attack progress: " + count + " of " + allPayloads.size() + " requests sent");
                } catch (Exception e) {
                    // Ignore
                }
            }

            try {
                String[] parts = payload.split(":", 2);
                if (parts.length != 2) {
                    continue;
                }

                String headerName = parts[0].trim();
                String headerValue = parts[1].trim();
                HttpRequest modifiedRequest = baseRequest.withAddedHeader(headerName, headerValue);
                HttpResponse response = api.http().sendRequest(modifiedRequest).response();
                resultCallback.accept(new AttackResult(getAttackType(), payload, modifiedRequest, response));
                count++;
            } catch (NullPointerException e) {
                break;
            } catch (Exception e) {
                try {
                    api.logging().logToError("Header attack error with payload: " + payload + " - " + e.getMessage());
                } catch (Exception logError) {
                    // Ignore
                }
            }
        }

        try {
            api.logging().logToOutput("Header Attack completed: " + count + " results sent");
        } catch (Exception e) {
            // Ignore
        }
    }

    @Override
    public String getAttackType() {
        return "Header";
    }

    /**
     * Build payload list with Collaborator payloads interleaved after each header group.
     * Groups regular payloads by header name, then adds Collaborator payload after each group.
     */
    private List<String> buildInterleavedPayloads(MontoyaApi api) {
        List<String> interleavedPayloads = new ArrayList<>();

        // Group payloads by header name (preserve insertion order)
        Map<String, List<String>> payloadsByHeader = new LinkedHashMap<>();
        for (String payload : headerPayloads) {
            String[] parts = payload.split(":", 2);
            if (parts.length == 2) {
                String headerName = parts[0].trim();
                payloadsByHeader.computeIfAbsent(headerName, k -> new ArrayList<>()).add(payload);
            }
        }

        // Generate Collaborator payloads if enabled
        Map<String, String> collaboratorPayloads = new HashMap<>();
        if (enableCollaborator) {
            collaboratorPayloads = generateCollaboratorPayloads(api);
            try {
                api.logging().logToOutput("Header Attack: Generated " + collaboratorPayloads.size() + " Collaborator payloads for interleaving");
            } catch (Exception e) {
                // Ignore
            }
        }

        // Interleave: add all regular payloads for a header, then add Collaborator payload for that header
        for (Map.Entry<String, List<String>> entry : payloadsByHeader.entrySet()) {
            String headerName = entry.getKey();
            List<String> regularPayloads = entry.getValue();

            // Add all regular payloads for this header
            interleavedPayloads.addAll(regularPayloads);

            // Add Collaborator payload for this header (if available)
            if (enableCollaborator && collaboratorPayloads.containsKey(headerName)) {
                interleavedPayloads.add(collaboratorPayloads.get(headerName));
            }
        }

        return interleavedPayloads;
    }

    /**
     * Generate Collaborator payloads for each unique header name.
     * Returns a map of header name -> Collaborator payload.
     */
    private Map<String, String> generateCollaboratorPayloads(MontoyaApi api) {
        Map<String, String> collaboratorPayloads = new HashMap<>();

        try {
            // Check if Collaborator is available
            if (api.collaborator() == null || api.collaborator().defaultPayloadGenerator() == null) {
                try {
                    api.logging().logToError("Burp Collaborator is not available. Please configure Collaborator in Burp Suite settings, or disable the 'Include Collaborator payloads' option. Note: Collaborator is only available in Burp Suite Professional.");
                } catch (Exception e) {
                    // Ignore logging error
                }
                return collaboratorPayloads;
            }

            // Get unique header names from existing payloads
            Set<String> headerNames = new HashSet<>();
            for (String payload : headerPayloads) {
                String[] parts = payload.split(":", 2);
                if (parts.length == 2) {
                    headerNames.add(parts[0].trim());
                }
            }

            try {
                api.logging().logToOutput("Generating Collaborator payloads for " + headerNames.size() + " unique headers");
            } catch (Exception e) {
                // Ignore logging error
            }

            // Generate one Collaborator payload per unique header name
            for (String headerName : headerNames) {
                try {
                    String collaboratorPayload = api.collaborator().defaultPayloadGenerator().generatePayload().toString();
                    // Store as "HeaderName: payload" value in the map
                    collaboratorPayloads.put(headerName, headerName + ": " + collaboratorPayload);
                } catch (Exception e) {
                    // Skip this header if payload generation fails
                }
            }

            try {
                api.logging().logToOutput("Generated " + collaboratorPayloads.size() + " Collaborator payloads");
            } catch (Exception e) {
                // Ignore logging error
            }

        } catch (Exception e) {
            try {
                api.logging().logToError("Error generating Collaborator payloads: " + e.getMessage());
            } catch (Exception logError) {
                // Ignore
            }
        }

        return collaboratorPayloads;
    }
}
