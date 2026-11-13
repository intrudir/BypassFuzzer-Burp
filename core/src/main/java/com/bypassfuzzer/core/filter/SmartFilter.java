package com.bypassfuzzer.core.filter;

import com.bypassfuzzer.core.scan.ResultView;

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
    private final Map<String, List<ResultView>> patternResults = new HashMap<>();

    public SmartFilter(FilterConfig config) {
        this.config = config;
    }

    /**
     * Track this result pattern.
     * Called for EVERY result regardless of filter state.
     */
    public void track(ResultView result) {
        // Control traffic must not consume the first-N slots reserved for scan results.
        if (result.getControlRole().isCalibration()) return;
        String key = createKey(result);
        patternDatabase.put(key, patternDatabase.getOrDefault(key, 0) + 1);

        // Store this result in the pattern's list (for the first maxRepeats occurrences)
        List<ResultView> results = patternResults.computeIfAbsent(key, k -> new ArrayList<>());
        if (results.size() < maxRepeats()) {
            results.add(result);
        }
    }

    @Override
    public boolean shouldShow(ResultView result) {
        if (result.getControlRole().isCalibration()) return true;
        if (!config.isSmartFilterEnabled()) {
            return true; // Filter disabled, show all
        }

        String key = createKey(result);
        List<ResultView> results = patternResults.get(key);

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
    private String createKey(ResultView result) {
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
            uniquePatterns, maxRepeats());
    }

    private int maxRepeats() {
        return Math.max(1, config.getSmartFilterRepeats());
    }
}
