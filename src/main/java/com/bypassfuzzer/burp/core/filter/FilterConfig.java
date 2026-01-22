package com.bypassfuzzer.burp.core.filter;

import java.util.HashSet;
import java.util.Set;

/**
 * Configuration for filtering attack results.
 */
public class FilterConfig {
    // Smart filter settings
    private boolean smartFilterEnabled = false;

    // Manual filter settings
    private boolean manualFilterEnabled = false;
    private Set<Integer> hiddenStatusCodes = new HashSet<>();
    private Set<Integer> shownStatusCodes = new HashSet<>();
    private Integer minContentLength = null;
    private Integer maxContentLength = null;
    private String contentTypeFilter = null;
    private String payloadContainsFilter = null;

    public boolean isSmartFilterEnabled() {
        return smartFilterEnabled;
    }

    public void setSmartFilterEnabled(boolean enabled) {
        this.smartFilterEnabled = enabled;
    }

    public boolean isManualFilterEnabled() {
        return manualFilterEnabled;
    }

    public void setManualFilterEnabled(boolean enabled) {
        this.manualFilterEnabled = enabled;
    }

    public Set<Integer> getHiddenStatusCodes() {
        return hiddenStatusCodes;
    }

    public void setHiddenStatusCodes(Set<Integer> codes) {
        this.hiddenStatusCodes = codes;
    }

    public Set<Integer> getShownStatusCodes() {
        return shownStatusCodes;
    }

    public void setShownStatusCodes(Set<Integer> codes) {
        this.shownStatusCodes = codes;
    }

    public Integer getMinContentLength() {
        return minContentLength;
    }

    public void setMinContentLength(Integer min) {
        this.minContentLength = min;
    }

    public Integer getMaxContentLength() {
        return maxContentLength;
    }

    public void setMaxContentLength(Integer max) {
        this.maxContentLength = max;
    }

    public String getContentTypeFilter() {
        return contentTypeFilter;
    }

    public void setContentTypeFilter(String filter) {
        this.contentTypeFilter = filter;
    }

    public String getPayloadContainsFilter() {
        return payloadContainsFilter;
    }

    public void setPayloadContainsFilter(String filter) {
        this.payloadContainsFilter = filter;
    }
}
