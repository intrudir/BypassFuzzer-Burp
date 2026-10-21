package com.bypassfuzzer.burp.core.filter;
import com.bypassfuzzer.core.filter.FilterConfig;

import com.bypassfuzzer.burp.core.attacks.AttackResult;

import java.awt.Color;

/**
 * Owns result filtering and highlight state outside Swing widgets.
 */
public class ResultFilterController {

    private final FilterConfig filterConfig = new FilterConfig();
    private final SmartFilter smartFilter = new SmartFilter(filterConfig);
    private final ManualFilter manualFilter = new ManualFilter(filterConfig);
    private final ResultHighlighter highlighter = new ResultHighlighter();
    private String highlightColorFilter = "All";

    public FilterConfig filterConfig() {
        return filterConfig;
    }

    public ResultHighlighter highlighter() {
        return highlighter;
    }

    public void setHighlightColorFilter(String highlightColorFilter) {
        this.highlightColorFilter = highlightColorFilter == null ? "All" : highlightColorFilter;
    }

    public void track(AttackResult result) {
        smartFilter.track(result);
    }

    public boolean shouldShow(AttackResult result) {
        if (!smartFilter.shouldShow(result)) {
            return false;
        }

        if (filterConfig.isManualFilterEnabled() && !manualFilter.shouldShow(result)) {
            return false;
        }

        if (filterConfig.isManualFilterEnabled() && !"All".equals(highlightColorFilter)) {
            Color filterColor = highlighter.colorFromName(highlightColorFilter);
            Color resultColor = highlighter.colorFor(result);
            return colorsMatch(resultColor, filterColor);
        }

        return true;
    }

    public void reset() {
        smartFilter.reset();
        highlighter.clearAll();
    }

    public String statusText(int shownResults, int totalResults) {
        boolean anyFilterActive = filterConfig.isSmartFilterEnabled() || filterConfig.isManualFilterEnabled();
        if (!anyFilterActive) {
            return "No filters active";
        }

        StringBuilder status = new StringBuilder();
        if (filterConfig.isSmartFilterEnabled()) {
            status.append("Smart: ").append(smartFilter.getStatistics());
        }
        if (filterConfig.isManualFilterEnabled()) {
            if (status.length() > 0) {
                status.append(" | ");
            }
            status.append("Manual: Active");
        }
        status.append(" | Showing ").append(shownResults).append(" of ").append(totalResults);
        return status.toString();
    }

    private boolean colorsMatch(Color c1, Color c2) {
        if (c1 == null || c2 == null) {
            return false;
        }
        return c1.getRed() == c2.getRed()
            && c1.getGreen() == c2.getGreen()
            && c1.getBlue() == c2.getBlue();
    }
}
