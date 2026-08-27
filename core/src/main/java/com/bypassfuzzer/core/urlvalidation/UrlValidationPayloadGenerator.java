package com.bypassfuzzer.core.urlvalidation;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Type;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Generates URL validation payloads from bundled PortSwigger source wordlists.
 */
public class UrlValidationPayloadGenerator {

    private static final String SOURCE_RESOURCE = "/payloads/url_validation_source_data.json";
    private static final String DEFAULT_ALLOWED_HOST = "example.com";
    private static final String CATEGORY = "CHEATSHEET";
    private static final Type RESOURCE_TYPE = new TypeToken<List<SourceWordlist>>() {
    }.getType();
    private static final Map<UrlValidationAttackSetting, List<SourcePayload>> WORDLISTS = loadWordlists();

    public List<UrlValidationPayload> generate(UrlValidationCandidate candidate, UrlValidationOptions options) {
        return generate(candidate, options, options::normalizedAttackerHost);
    }

    public List<UrlValidationPayload> generate(UrlValidationCandidate candidate,
                                               UrlValidationOptions options,
                                               Supplier<String> attackerHostSupplier) {
        String allowedHost = preferredAllowedHost(candidate, options);
        Set<UrlValidationEncoding> encodings = options.effectiveEncodings();
        String scheme = options.normalizedAttackerScheme();
        List<UrlValidationPayload> payloads = new ArrayList<>();
        Set<UrlValidationAttackSetting> selectedSettings = options.normalizedAttackSettings();

        for (UrlValidationEncoding encoding : encodings) {
            for (UrlValidationAttackSetting attackSetting : selectedSettings) {
                if (attackSetting == UrlValidationAttackSetting.NORMALIZATION_ATTACK) {
                    addNormalizationAttackPayloads(payloads, options, allowedHost, attackerHostSupplier, scheme, encoding);
                    continue;
                }
                List<SourcePayload> sourcePayloads = WORDLISTS.getOrDefault(attackSetting, List.of());
                for (SourcePayload sourcePayload : sourcePayloads) {
                    for (UrlValidationContext family : options.normalizedPayloadFamilies()) {
                        if (!sourcePayload.supports(family)) {
                            continue;
                        }
                        String attackerHost = attackerHostSupplier.get();
                        String value = renderPayload(attackSetting, sourcePayload, family, scheme, allowedHost, attackerHost);
                        payloads.add(new UrlValidationPayload(family, CATEGORY, encoding, encode(value, encoding)));
                    }
                }
            }
        }

        // Deduplicate: different source templates can collapse to the same
        // rendered string (e.g., LOOPBACK's <attacker> and DOMAIN_ALLOW_LIST's
        // <attacker> both become http://127.0.0.1). Send each unique
        // (family + encoding + value) only once.
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        List<UrlValidationPayload> deduped = new ArrayList<>();
        for (UrlValidationPayload p : payloads) {
            String key = p.family().name() + "|" + p.encoding().name() + "|" + p.value();
            if (seen.add(key)) {
                deduped.add(p);
            }
        }
        return deduped;
    }

    /**
     * Unicode normalization bypass: emit payloads whose attacker/allowed host
     * uses Unicode presentation-form characters (fullwidth Latin) that a strict
     * string-compare allow/deny list rejects but a normalizer (NFKC or similar)
     * collapses to plain ASCII before the request is routed or redirected.
     *
     * Targets the scenario where:
     *   validate(input) { if (denyList.contains(input)) return reject; }
     *   route(normalize(input));
     * The normalizer runs after the validator, so presentation-form bytes
     * bypass the validator and still resolve to the original ASCII target.
     */
    private void addNormalizationAttackPayloads(List<UrlValidationPayload> payloads,
                                                UrlValidationOptions options,
                                                String allowedHost,
                                                Supplier<String> attackerHostSupplier,
                                                String scheme,
                                                UrlValidationEncoding encoding) {
        List<String> allowedVariants = UnicodeCompatibilityVariants.fullwidthVariants(allowedHost);

        for (UrlValidationContext family : options.normalizedPayloadFamilies()) {
            // Per-payload attacker host keeps each variant distinct when the caller
            // uses a collaborator supplier that mints fresh domains.
            for (String attackerVariant : UnicodeCompatibilityVariants.fullwidthVariants(attackerHostSupplier.get())) {
                addNormalizationVariant(payloads, family, encoding, scheme, attackerVariant);
            }
            for (String allowedVariant : allowedVariants) {
                String attackerHost = attackerHostSupplier.get();
                // Attacker-domain-after-fullwidth-allowed: cousin-domain shape
                // where the validator's "starts with trusted.com" check fails
                // against the fullwidth form but the normalizer resolves it.
                addNormalizationVariant(payloads, family, encoding, scheme,
                    allowedVariant + "." + attackerHost);
                // Fullwidth allowed on the Host header / raw CORS origin
                addNormalizationVariant(payloads, family, encoding, scheme, allowedVariant);
            }
        }
    }

    private void addNormalizationVariant(List<UrlValidationPayload> payloads,
                                         UrlValidationContext family,
                                         UrlValidationEncoding encoding,
                                         String scheme,
                                         String host) {
        String value = family == UrlValidationContext.HOSTNAME
            ? host
            : scheme + "://" + host + "/";
        payloads.add(new UrlValidationPayload(family, CATEGORY, encoding, encode(value, encoding)));
    }


    private String renderPayload(UrlValidationAttackSetting attackSetting,
                                 SourcePayload sourcePayload,
                                 UrlValidationContext family,
                                 String scheme,
                                 String allowedHost,
                                 String attackerHost) {
        String prefix = normalizeComponent(sourcePayload.prefix());
        String suffix = normalizeComponent(sourcePayload.suffix());
        String payload = sourcePayload.payload()
            .replace("<attacker>", attackerHost)
            .replace("<allowed>", allowedHost);

        String port = sourcePayload.port() == null ? "" : ":" + sourcePayload.port();
        if (attackSetting == UrlValidationAttackSetting.CLOUD_METADATA_ENDPOINTS
            && family == UrlValidationContext.HOSTNAME) {
            return payload + port;
        }

        if (prefix.isEmpty() && family != UrlValidationContext.HOSTNAME && !"null".equals(payload)) {
            prefix = scheme + "://";
        }

        return prefix + payload + port + suffix;
    }

    private String normalizeComponent(String value) {
        return value == null ? "" : value;
    }

    private String preferredAllowedHost(UrlValidationCandidate candidate, UrlValidationOptions options) {
        String configured = options.normalizedAllowedHost();
        if (!configured.isEmpty()) {
            return configured;
        }

        String extracted = extractHost(candidate.originalValue());
        return extracted.isEmpty() ? DEFAULT_ALLOWED_HOST : extracted;
    }

    private String extractHost(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }

        String trimmed = value.trim();
        if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            try {
                URI uri = URI.create(trimmed);
                return uri.getHost() == null ? "" : uri.getHost();
            } catch (IllegalArgumentException e) {
                return "";
            }
        }

        if (trimmed.startsWith("//")) {
            String withoutSlashes = trimmed.substring(2);
            int slashIndex = withoutSlashes.indexOf('/');
            return slashIndex >= 0 ? withoutSlashes.substring(0, slashIndex) : withoutSlashes;
        }

        return trimmed.contains("/") ? "" : trimmed;
    }

    private String encode(String value, UrlValidationEncoding encoding) {
        return switch (encoding) {
            case RAW -> value;
            case INTRUDERS -> percentEncodeSelective(value, ":/?#[]!$&'()*+,;=-._~\\");
            case EVERYTHING -> percentEncode(value, true);
            case SPECIAL_CHARS -> percentEncodeSelective(value, ":/?#[]@!$&'()*+,;=-._~\\");
            case UNICODE_ESCAPE -> unicodeEscape(value);
        };
    }

    private String percentEncode(String value, boolean encodeAlphaNumeric) {
        StringBuilder encoded = new StringBuilder();
        for (byte current : value.getBytes(StandardCharsets.UTF_8)) {
            int unsigned = current & 0xff;
            char character = (char) unsigned;
            boolean alphaNumeric = (character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z')
                || (character >= '0' && character <= '9');

            if (!encodeAlphaNumeric && alphaNumeric) {
                encoded.append(character);
            } else {
                encoded.append('%');
                encoded.append(Character.toUpperCase(Character.forDigit((unsigned >> 4) & 0xf, 16)));
                encoded.append(Character.toUpperCase(Character.forDigit(unsigned & 0xf, 16)));
            }
        }
        return encoded.toString();
    }

    private String percentEncodeSelective(String value, String safeCharacters) {
        StringBuilder encoded = new StringBuilder();
        for (byte current : value.getBytes(StandardCharsets.UTF_8)) {
            int unsigned = current & 0xff;
            char character = (char) unsigned;
            boolean alphaNumeric = (character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z')
                || (character >= '0' && character <= '9');

            if (alphaNumeric || safeCharacters.indexOf(character) >= 0) {
                encoded.append(character);
            } else {
                encoded.append('%');
                encoded.append(Character.toUpperCase(Character.forDigit((unsigned >> 4) & 0xf, 16)));
                encoded.append(Character.toUpperCase(Character.forDigit(unsigned & 0xf, 16)));
            }
        }
        return encoded.toString();
    }

    private String unicodeEscape(String value) {
        StringBuilder escaped = new StringBuilder();
        for (char current : value.toCharArray()) {
            switch (current) {
                case '\t' -> escaped.append("\\t");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                default -> {
                    if (current < 0x20 || current > 0x7e) {
                        escaped.append(String.format("\\u%04X", (int) current));
                    } else {
                        escaped.append(current);
                    }
                }
            }
        }
        return escaped.toString();
    }

    private static Map<UrlValidationAttackSetting, List<SourcePayload>> loadWordlists() {
        InputStream inputStream = UrlValidationPayloadGenerator.class.getResourceAsStream(SOURCE_RESOURCE);
        if (inputStream == null) {
            throw new IllegalStateException("Missing URL validation source payload resource: " + SOURCE_RESOURCE);
        }

        try (Reader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
            List<SourceWordlist> wordlists = new Gson().fromJson(reader, RESOURCE_TYPE);
            Map<UrlValidationAttackSetting, List<SourcePayload>> mapped = new EnumMap<>(UrlValidationAttackSetting.class);
            for (SourceWordlist wordlist : wordlists) {
                mapped.put(wordlist.setting(), List.copyOf(wordlist.payloads()));
            }
            return Map.copyOf(mapped);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load URL validation source payloads", e);
        }
    }

    private record SourceWordlist(
        UrlValidationAttackSetting setting,
        String name,
        List<SourcePayload> payloads
    ) {
    }

    private record SourcePayload(
        String id,
        String payload,
        String description,
        String prefix,
        String suffix,
        Integer port,
        List<String> tags
    ) {
        boolean supports(UrlValidationContext family) {
            return tags != null && tags.contains(tagFor(family));
        }

        private String tagFor(UrlValidationContext family) {
            return switch (family) {
                case ABSOLUTE_URL -> "URL";
                case HOSTNAME -> "HOST";
                case CORS_ORIGIN -> "CORS";
            };
        }
    }
}
