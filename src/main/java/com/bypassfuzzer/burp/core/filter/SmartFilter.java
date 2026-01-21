package com.bypassfuzzer.burp.core.filter;

import com.bypassfuzzer.burp.core.attacks.AttackResult;

import java.util.*;

/**
 * Smart filter that auto-detects interesting responses based on repeat patterns.
 * All credit for this filter logic goes to @defparam:
 * https://gist.github.com/defparam/8067cc4eb0140399f2bcd5f66a860db4
 *
 * Tracks patterns continuously regardless of filter state.
 * When enabled, shows first N occurrences of each unique pattern.
 */
public class SmartFilter implements ResponseFilter {
    private final FilterConfig config;
    private final Map<String, Integer> patternDatabase = new HashMap<>();
    private final Map<String, List<AttackResult>> patternResults = new HashMap<>();
    private final int maxRepeats;

    public SmartFilter(FilterConfig config) {
        this.config = config;
        this.maxRepeats = 10; // Show first 10 of each pattern, then mute
    }

    /**
     * Track this result pattern.
     * Called for EVERY result regardless of filter state.
     */
    public void track(AttackResult result) {
        String key = createKey(result);
        patternDatabase.put(key, patternDatabase.getOrDefault(key, 0) + 1);

        // Store this result in the pattern's list (for the first maxRepeats occurrences)
        List<AttackResult> results = patternResults.computeIfAbsent(key, k -> new ArrayList<>());
        if (results.size() < maxRepeats) {
            results.add(result);
        }
    }

    @Override
    public boolean shouldShow(AttackResult result) {
        if (!config.isSmartFilterEnabled()) {
            return true; // Filter disabled, show all
        }

        String key = createKey(result);
        List<AttackResult> results = patternResults.get(key);

        // Show if this result is in the first maxRepeats occurrences of this pattern
        return results != null && results.contains(result);
    }

    @Override
    public String getName() {
        return "Smart Filter";
    }

    /**
     * Create unique key from status code + content length + content type.
     * Matches Python implementation: str(status) + str(wordlen) + str(content_type)
     */
    private String createKey(AttackResult result) {
        String contentType = result.getContentType() != null ? result.getContentType() : "null";
        return result.getStatusCode() + "" + result.getContentLength() + "" + contentType;
    }

    /**
     * Reset all tracked patterns.
     */
    public void reset() {
        patternDatabase.clear();
        patternResults.clear();
    }

    /**
     * Get statistics for display.
     */
    public String getStatistics() {
        int uniquePatterns = patternDatabase.size();
        if (uniquePatterns == 0) {
            return "No patterns tracked";
        }
        return String.format("%d unique patterns tracked (showing first %d of each)",
            uniquePatterns, maxRepeats);
    }
}
