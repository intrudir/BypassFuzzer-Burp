package com.bypassfuzzer.burp.core.filter;

import com.bypassfuzzer.burp.core.attacks.AttackResult;

/**
 * Interface for filtering attack results.
 */
public interface ResponseFilter {
    /**
     * Determine if a result should be shown (passes the filter).
     * @param result The attack result to evaluate
     * @return true if result should be shown, false if it should be filtered out
     */
    boolean shouldShow(AttackResult result);

    /**
     * Get the name of this filter.
     */
    String getName();
}
