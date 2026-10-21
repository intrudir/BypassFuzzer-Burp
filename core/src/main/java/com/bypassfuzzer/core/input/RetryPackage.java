package com.bypassfuzzer.core.input;

import java.util.List;

/** Burp's exact-request retry interchange format. */
public record RetryPackage(String version, String type, List<RetryPackageEntry> entries) {
    public RetryPackage {
        if (!"1".equals(version) || !"bypassfuzzer-retry-queue".equals(type) || entries == null)
            throw new IllegalArgumentException("Expected a BypassFuzzer version-1 retry package");
        entries = List.copyOf(entries);
    }
}
