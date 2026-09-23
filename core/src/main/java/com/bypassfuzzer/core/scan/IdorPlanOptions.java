package com.bypassfuzzer.core.scan;

import java.util.Set;

public record IdorPlanOptions(String authorizedId, String targetId, String locationKey,
                              Set<String> families, int maxMutations, boolean includeMethodChanges,
                              String uniqueJsonPointer, String uniqueToken) {
    /** No user-facing IDOR mutation cap; the finite selected playbooks determine the plan size. */
    public static final int UNLIMITED = Integer.MAX_VALUE;
    public IdorPlanOptions(String authorizedId, String targetId, String locationKey,
                           Set<String> families, int maxMutations, boolean includeMethodChanges) {
        this(authorizedId, targetId, locationKey, families, maxMutations, includeMethodChanges, null, null);
    }
    public IdorPlanOptions {
        families = families == null ? Set.of() : Set.copyOf(families);
        maxMutations = Math.max(0, maxMutations);
        if (uniqueJsonPointer != null && !uniqueJsonPointer.isBlank()
            && (uniqueToken == null || uniqueToken.isBlank()))
            throw new IllegalArgumentException("A run token is required for unique JSON values");
    }
}
