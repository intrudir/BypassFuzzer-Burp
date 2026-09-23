package com.bypassfuzzer.burp.core.idor;

/**
 * User-supplied IDOR analysis settings for a single run.
 */
public record IdorOptions(
    String authorizedIdentifier,
    String targetIdentifier,
    IdorRunOptions runOptions,
    String locationKey,
    java.util.Set<String> selectedFamilies,
    int maxMutations,
    boolean includeMethodChanges,
    String uniqueJsonPointer,
    String uniqueToken
) {
    public IdorOptions(String authorizedIdentifier, String targetIdentifier, IdorRunOptions runOptions,
                       String locationKey, java.util.Set<String> selectedFamilies, int maxMutations,
                       boolean includeMethodChanges) {
        this(authorizedIdentifier, targetIdentifier, runOptions, locationKey, selectedFamilies,
            maxMutations, includeMethodChanges, null, null);
    }
    public IdorOptions(String authorizedIdentifier, String targetIdentifier, IdorRunOptions runOptions) {
        this(authorizedIdentifier, targetIdentifier, runOptions, null, java.util.Set.of(),
            com.bypassfuzzer.core.scan.IdorPlanOptions.UNLIMITED, false,
            null, null);
    }

    public IdorOptions {
        selectedFamilies = selectedFamilies == null ? java.util.Set.of() : java.util.Set.copyOf(selectedFamilies);
        maxMutations = Math.max(0, maxMutations);
    }

    public String normalizedAuthorizedIdentifier() {
        return authorizedIdentifier == null ? "" : authorizedIdentifier.trim();
    }

    public String normalizedTargetIdentifier() {
        return targetIdentifier == null ? "" : targetIdentifier.trim();
    }
}
