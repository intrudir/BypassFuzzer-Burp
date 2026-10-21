package com.bypassfuzzer.core.filter;

import com.bypassfuzzer.core.scan.ResultView;

/**
 * Interface for filtering attack results.
 */
public interface ResponseFilter {
    /**
     * Determine if a result should be shown (passes the filter).
     * @param result The attack result to evaluate
     * @return true if result should be shown, false if it should be filtered out
     */
    boolean shouldShow(ResultView result);

    /**
     * Get the name of this filter.
     */
    String getName();
}
