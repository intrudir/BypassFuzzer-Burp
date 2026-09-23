package com.bypassfuzzer.burp.core.urlvalidation;

import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/** Burp enum adapter for the shared URL Validation payload catalog. */
public class UrlValidationPayloadGenerator {
    private final com.bypassfuzzer.core.urlvalidation.UrlValidationPayloadGenerator delegate =
        new com.bypassfuzzer.core.urlvalidation.UrlValidationPayloadGenerator();

    public List<UrlValidationPayload> generate(UrlValidationCandidate candidate, UrlValidationOptions options) {
        return generate(candidate, options, options::normalizedAttackerHost);
    }

    public List<UrlValidationPayload> generate(UrlValidationCandidate candidate, UrlValidationOptions options,
                                               Supplier<String> attackerHostSupplier) {
        var coreCandidate = new com.bypassfuzzer.core.urlvalidation.UrlValidationCandidate(
            candidate.sinkName(), candidate.originalValue(), candidate.locationLabel());
        return delegate.generate(coreCandidate, toCoreOptions(options, options.normalizedAttackerHost()),
            attackerHostSupplier).stream().map(payload -> new UrlValidationPayload(
                UrlValidationContext.valueOf(payload.family().name()), payload.category(),
                UrlValidationEncoding.valueOf(payload.encoding().name()), payload.value())).toList();
    }

    public static com.bypassfuzzer.core.urlvalidation.UrlValidationOptions toCoreOptions(
        UrlValidationOptions options, String attackerHost) {
        return new com.bypassfuzzer.core.urlvalidation.UrlValidationOptions(
            options.normalizedMarkerText(), options.normalizedAllowedHost(), attackerHost,
            options.normalizedAttackerScheme(),
            map(options.normalizedPayloadFamilies(), com.bypassfuzzer.core.urlvalidation.UrlValidationContext.class),
            map(options.normalizedAttackSettings(), com.bypassfuzzer.core.urlvalidation.UrlValidationAttackSetting.class),
            map(options.effectiveEncodings(), com.bypassfuzzer.core.urlvalidation.UrlValidationEncoding.class));
    }

    private static <E extends Enum<E>> Set<E> map(Set<? extends Enum<?>> values, Class<E> type) {
        return values.stream().map(value -> Enum.valueOf(type, value.name())).collect(Collectors.toSet());
    }
}
